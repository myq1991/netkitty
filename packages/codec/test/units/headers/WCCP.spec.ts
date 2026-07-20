import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

const COMPONENTS: string = '000000040000000000010018000000000000000000000000000000000000000000000000'

// WCCP v2 (udp:2048) Here-I-Am — 8-byte header (type/version/length) + component TLV region kept verbatim.
test('WCCP Here-I-Am: header + components + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('wccp/here-i-am').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'wccp'])
    const wccp: any = Layer(decoded, 'wccp').data
    assert.strictEqual(wccp.type, 10, 'Here-I-Am')
    assert.strictEqual(wccp.version, 0x0200, 'WCCP v2')
    assert.strictEqual(wccp.length, 36, 'component region octet count (excludes the 8-byte header)')
    assert.strictEqual(wccp.components, COMPONENTS, 'Security Info + Service Info components, verbatim')
})

// Crafting: an I-See-You (type 11) with an empty component region and the Length auto-computed from the
// (empty) components — the minimal well-formed WCCP message must re-encode byte-identically.
test('WCCP faithfully encodes a crafted I-See-You and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.2', dip: '10.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 2048, dstport: 40000}},
        {id: 'wccp', data: {type: 11, version: 0x0200}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'wccp'])
    const wccp: any = Layer(decoded, 'wccp').data
    assert.strictEqual(wccp.type, 11, 'I-See-You')
    assert.strictEqual(wccp.length, 0, 'auto-computed Length = 0 (header only, empty components)')
    assert.strictEqual(wccp.components, '', 'empty component region')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted message supplies an explicit Length that lies (0 while components
// are present) — it must be honored verbatim, and the components stay bounded by the UDP payload so the
// full component region still round-trips byte-for-byte.
test('WCCP honors an explicitly supplied (lying) Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 2048, dstport: 2048}},
        {id: 'wccp', data: {type: 10, version: 0x0200, length: 0, components: COMPONENTS}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const wccp: any = Layer(decoded, 'wccp').data
    assert.strictEqual(wccp.length, 0, 'supplied Length honored (not derived over)')
    // Length lies (0), so the message ends at offset 8; the remaining component bytes fall through to raw.
    assert.strictEqual(wccp.components, '', 'components bounded by the (lying) Length')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/2048 payload shorter than the 8-byte header must NOT be claimed as WCCP (falls through
// to raw); and a truncated WCCP message must survive decode without throwing.
test('WCCP rejects a sub-8-byte payload, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 2048, dstport: 2048}},
        {id: 'raw', data: {data: 'deadbeef01'}}                 // 5 bytes < 8-byte WCCP header
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'wccp'), 'sub-8-byte payload must not be claimed as WCCP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('wccp/here-i-am').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})
