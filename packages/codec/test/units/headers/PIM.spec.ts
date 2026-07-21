import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// PIM-SM v2 (ipproto 103) Hello message — 4-byte header (version/type + reserved + checksum) followed
// by the Hello options body, kept verbatim. Decode layering + byte-perfect round-trip.
test('PIM Hello: header + verbatim body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('pim/hello').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'pim'])
    const pim: any = Layer(decoded, 'pim').data
    assert.strictEqual(pim.version, 2, 'PIMv2')
    assert.strictEqual(pim.type, 0, 'Hello')
    assert.strictEqual(pim.reserved, '00', 'reserved byte kept verbatim')
    assert.strictEqual(pim.checksum, 0x67ca, 'checksum honored verbatim')
    assert.strictEqual(pim.body, '000100020069001300040000000100140004aabbccdd', 'Hello options body verbatim')
})

// Crafting: a minimal PIM message (version 2, type 0, empty body) — the fixed 4-byte header alone must
// re-encode byte-identically, defaulting version to 2 and honoring the supplied checksum verbatim.
test('PIM faithfully encodes a crafted minimal Hello and honors the checksum verbatim', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:0d', smac: '00:00:00:00:00:01', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '224.0.0.13', ttl: 1, protocol: 103}},
        {id: 'pim', data: {version: 2, type: 0, reserved: '00', checksum: 0x1234}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'pim'])
    const pim: any = Layer(decoded, 'pim').data
    assert.strictEqual(pim.version, 2, 'PIMv2')
    assert.strictEqual(pim.type, 0, 'Hello')
    assert.strictEqual(pim.checksum, 0x1234, 'supplied checksum honored, not recomputed')
    assert.strictEqual(pim.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor semantics for a non-Hello type + non-canonical reserved byte: a crafted Join/Prune (type 3)
// with a body and a non-zero reserved byte must round-trip byte-for-byte (reserved re-emitted verbatim).
test('PIM honors a crafted Join/Prune with a non-zero reserved byte and a body', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:0d', smac: '00:00:00:00:00:01', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.2', dip: '224.0.0.13', ttl: 1, protocol: 103}},
        {id: 'pim', data: {version: 2, type: 3, reserved: 'ab', checksum: 0xbeef, body: '0102030405060708'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const pim: any = Layer(decoded, 'pim').data
    assert.strictEqual(pim.type, 3, 'Join/Prune')
    assert.strictEqual(pim.reserved, 'ab', 'non-canonical reserved byte kept verbatim')
    assert.strictEqual(pim.checksum, 0xbeef, 'checksum honored verbatim')
    assert.strictEqual(pim.body, '0102030405060708', 'body verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a truncated PIM message must survive decode without throwing; and an IP/103 payload shorter
// than the 4-byte fixed header must NOT be claimed as PIM (falls through to raw).
test('PIM truncation survives, and a sub-header IP/103 payload is not claimed as PIM', async (): Promise<void> => {
    const full: Buffer = LoadPacket('pim/hello').buffer
    // truncate mid-body — decode must not throw and must still produce layers
    await AssertDecodeSurvives(full.subarray(0, full.length - 5))
    // truncate to just 2 bytes of PIM payload (< 4-byte header): PIM must not match, trailing goes raw
    const decoded: CodecDecodeResult[] = await codec.decode(full.subarray(0, 36))
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'pim'), 'sub-header payload must not be claimed as PIM')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw', 'the 2 stray bytes fall through to raw')
})
