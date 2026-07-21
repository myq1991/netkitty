import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, Layer, LayerIds, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// MPLS unicast (ethertype 0x8847) single-label shim: one label stack entry (S=1) then an inner IPv4
// payload. The label stack round-trips byte-for-byte; the entry decodes to structured label/tc/s/ttl.
test('MPLS single label: decodes the stack entry and round-trips byte-perfect', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('mpls/unicast-single-label').buffer)
    // eth then mpls; the inner IPv4 payload is left to the codec's recursion (inner IP dispatch is a
    // serial follow-up), so assert only the eth/mpls prefix rather than the full inner chain.
    assert.deepStrictEqual(LayerIds(decoded).slice(0, 2), ['eth', 'mpls'], 'eth then mpls')
    const mpls: any = Layer(decoded, 'mpls').data
    assert.strictEqual(mpls.entries.length, 1, 'single-entry stack')
    assert.deepStrictEqual(mpls.entries[0], {label: 16, tc: 0, s: 1, ttl: 64}, 'label 16, TC 0, S 1, TTL 64')
})

// A two-label stack: the walk repeats until the entry whose S=1 (bottom of stack), decoding both
// entries; the whole shim round-trips byte-for-byte.
test('MPLS two labels: walks the stack until S=1 and round-trips byte-perfect', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('mpls/unicast-two-labels').buffer)
    const mpls: any = Layer(decoded, 'mpls').data
    assert.strictEqual(mpls.entries.length, 2, 'two-entry stack')
    assert.deepStrictEqual(mpls.entries[0], {label: 16, tc: 0, s: 0, ttl: 64}, 'outer: S 0 (not bottom)')
    assert.deepStrictEqual(mpls.entries[1], {label: 100, tc: 5, s: 1, ttl: 63}, 'inner: label 100, TC 5, S 1, TTL 63')
})

// Faithful executor: a crafted single-label frame (no inner payload) must re-encode byte-identically,
// preserving every packed field (label/tc/s/ttl) exactly.
test('MPLS faithfully encodes a crafted single-label stack', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '8847'}},
        {id: 'mpls', data: {entries: [{label: 1000, tc: 2, s: 1, ttl: 255}]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.deepStrictEqual(LayerIds(decoded), ['eth', 'mpls'], 'eth then mpls (no inner payload)')
    const mpls: any = Layer(decoded, 'mpls').data
    assert.deepStrictEqual(mpls.entries[0], {label: 1000, tc: 2, s: 1, ttl: 255}, 'every packed field preserved')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Faithful executor: a malformed stack that never sets S=1 (both entries S=0, then no payload) is
// re-emitted verbatim — the codec does not invent a bottom-of-stack bit.
test('MPLS faithfully re-emits a malformed stack that never sets S=1', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '8847'}},
        {id: 'mpls', data: {entries: [{label: 1, tc: 0, s: 0, ttl: 10}, {label: 2, tc: 0, s: 0, ttl: 20}]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const mpls: any = Layer(decoded, 'mpls').data
    assert.strictEqual(mpls.entries.length, 2, 'both S=0 entries decoded (walk stops at frame end)')
    assert.strictEqual(mpls.entries[1].s, 0, 'no S=1 invented')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a truncated frame (the label stack entry is cut mid-way) must survive decode without
// throwing — the incomplete entry is not consumed and the frame still produces a best-effort result.
test('MPLS truncation survives decode', async (): Promise<void> => {
    const full: Buffer = LoadPacket('mpls/unicast-single-label').buffer
    await AssertDecodeSurvives(full.subarray(0, 16))  // eth (14 bytes) + only 2 of the 4 entry bytes
    await AssertDecodeSurvives(full.subarray(0, 18))  // eth + one complete entry, inner payload cut off
})

// Regression (was a decode→encode throw): a frame with a short trailer after the S=1 entry — fewer
// bytes than a full inner packet — is owned by MPLS as `payload` hex and re-encodes byte-perfectly.
// Previously the trailer fell to the codec's recursion and was claimed by the greedy EthernetII content
// heuristic into an un-re-encodable layer, so codec.encode() threw an Ajv error.
test('MPLS short trailer after the stack round-trips without a re-encode throw', async (): Promise<void> => {
    const full: Buffer = LoadPacket('mpls/unicast-single-label').buffer
    const shortTrailer: Buffer = full.subarray(0, 19)  // eth (14) + one S=1 entry (4) + a single trailing byte
    const decoded: CodecDecodeResult[] = await codec.decode(shortTrailer)
    assert.deepStrictEqual(LayerIds(decoded), ['eth', 'mpls'], 'MPLS owns the trailer as payload — no phantom layer')
    const mpls: any = Layer(decoded, 'mpls').data
    assert.strictEqual(mpls.entries.length, 1, 'single S=1 entry')
    assert.strictEqual(mpls.payload, full.subarray(18, 19).toString('hex'), 'the short trailer is kept as MPLS payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), shortTrailer.toString('hex'), 'byte-perfect, no throw')
})

// Negative: a non-MPLS EtherType must NOT be claimed as MPLS (the match is EtherType-gated). A raw
// IPv4-looking payload under EtherType 0x0800 must not decode an 'mpls' layer.
test('MPLS is not claimed on a non-8847/8848 EtherType', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '88b5'}},
        {id: 'raw', data: {data: '00010140deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'mpls'), 'non-8847/8848 EtherType must not be MPLS')
})
