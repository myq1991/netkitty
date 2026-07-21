import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// LACP (Slow Protocols, ethertype 0x8809) LACPDU — subtype/version + Actor/Partner/Collector/Terminator
// TLVs + reserved padding, carried directly in an Ethernet II frame.
test('LACP LACPDU: subtype/version + TLV chain + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('lacp/lacpdu').buffer)
    AssertLayers(decoded, ['eth', 'lacp'])
    const lacp: any = Layer(decoded, 'lacp').data
    assert.strictEqual(lacp.subtype, 1, 'Subtype = LACP')
    assert.strictEqual(lacp.version, 1, 'Version 1')
    assert.strictEqual(lacp.tlvs.length, 4, 'Actor + Partner + Collector + Terminator')
    assert.strictEqual(lacp.tlvs[0].type, 1, 'Actor Information')
    assert.strictEqual(lacp.tlvs[0].length, 0x14, 'Actor length incl 2 header octets')
    assert.strictEqual(lacp.tlvs[0].value, '8000000000000001000100ff00013d000000', 'Actor value (18 bytes)')
    assert.strictEqual(lacp.tlvs[1].type, 2, 'Partner Information')
    assert.strictEqual(lacp.tlvs[2].type, 3, 'Collector Information')
    assert.strictEqual(lacp.tlvs[2].length, 0x10, 'Collector length')
    assert.strictEqual(lacp.tlvs[3].type, 0, 'Terminator')
    assert.strictEqual(lacp.tlvs[3].length, 0, 'Terminator length 0')
    assert.strictEqual(lacp.reserved, '00'.repeat(50), '50 reserved padding octets')
})

// Crafting: a minimal LACPDU with just a Terminator TLV; the Length is auto-derived (0 for Terminator,
// value+2 for a value-bearing TLV) — the crafted PDU must re-encode byte-identically.
test('LACP faithfully encodes a crafted LACPDU and derives TLV Lengths', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:02', smac: '00:00:00:00:00:aa', etherType: '8809'}},
        {id: 'lacp', data: {subtype: 1, version: 1, tlvs: [
            {type: 1, value: '8000000000000001000100ff00013d000000'},
            {type: 0}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'lacp'])
    const lacp: any = Layer(decoded, 'lacp').data
    assert.strictEqual(lacp.tlvs[0].length, 0x14, 'Actor Length derived = value(18) + 2')
    assert.strictEqual(lacp.tlvs[1].type, 0, 'Terminator')
    assert.strictEqual(lacp.tlvs[1].length, 0, 'Terminator Length derived = 0')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A TLV whose supplied Length overruns the remaining frame cannot be structurally re-parsed — the walk
// is bounded by the declared Length, so an overrun aborts it (LACP TLV Lengths are fixed by the
// standard; an honest LACPDU never lies). The bytes are never lost, though: they fall through into
// `reserved` and the frame still round-trips byte-for-byte. This documents the faithful-executor
// behavior (encode emits the lying Length verbatim) without asserting an impossible structured read.
test('LACP: a TLV Length overrunning the frame falls into reserved and still round-trips', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:02', smac: '00:00:00:00:00:aa', etherType: '8809'}},
        {id: 'lacp', data: {subtype: 1, version: 1, tlvs: [
            {type: 1, length: 0x99, value: '8000000000000001000100ff00013d000000'},
            {type: 0, length: 0}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'lacp'])
    const lacp: any = Layer(decoded, 'lacp').data
    assert.strictEqual(lacp.tlvs.length, 0, 'the overrun-Length TLV aborts the structured walk — no phantom entry')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect via the reserved fallback')
})

// Negative: an 0x8809 frame whose Subtype is 2 (Marker) must NOT be claimed as LACP (falls through to
// raw); a truncated LACPDU and a garbage 0x8809 payload must survive decode without throwing.
test('LACP rejects Subtype != 1, and truncation / garbage survive', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:02', smac: '00:00:00:00:00:aa', etherType: '8809'}},
        // subtype 3 (neither LACP=1 nor Marker=2) then arbitrary bytes — not claimed by any Slow Protocol
        {id: 'raw', data: {data: '030100000000000000000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'lacp'), 'non-LACP subtype must not be claimed as LACP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('lacp/lacpdu').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 30))
    await AssertDecodeSurvives(Buffer.concat([full.subarray(0, 14), Buffer.from('01ffabcd', 'hex')]))
})
