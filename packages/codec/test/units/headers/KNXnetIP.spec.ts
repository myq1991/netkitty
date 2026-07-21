import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// KNXnet/IP (udp:3671) SEARCH_REQUEST — 6-byte header (header length + version + service type + total
// length) + HPAI discovery endpoint body. Byte-perfect round-trip and per-field decode.
test('KNXnetIP SEARCH_REQUEST: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('knxnetip/search-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'knxnetip'])
    const knx: any = Layer(decoded, 'knxnetip').data
    assert.strictEqual(knx.headerLength, 6, 'header length 0x06')
    assert.strictEqual(knx.protocolVersion, 16, 'protocol version 0x10 (1.0)')
    assert.strictEqual(knx.serviceType, 0x0201, 'SEARCH_REQUEST')
    assert.strictEqual(knx.totalLength, 14, 'total length incl 6-byte header')
    assert.strictEqual(knx.body, '0801c0a8000a0e57', 'HPAI: len 8, UDP/IPv4, 192.168.0.10:3671')
})

// Crafting: a ROUTING_INDICATION with an empty body and the Total Length auto-computed from the (empty)
// body — the minimal well-formed KNXnet/IP frame must re-encode byte-identically.
test('KNXnetIP faithfully encodes a crafted header-only frame and auto-computes the Total Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.10', dip: '224.0.23.12', protocol: 17}},
        {id: 'udp', data: {srcport: 3671, dstport: 3671}},
        {id: 'knxnetip', data: {headerLength: 6, protocolVersion: 16, serviceType: 0x0530}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'knxnetip'])
    const knx: any = Layer(decoded, 'knxnetip').data
    assert.strictEqual(knx.serviceType, 0x0530, 'ROUTING_INDICATION')
    assert.strictEqual(knx.totalLength, 6, 'auto-computed Total Length = 6 (header only, empty body)')
    assert.strictEqual(knx.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Total Length: a crafted frame supplies an explicit Total Length — it must be honored
// verbatim (not overwritten by the derived value) so a frame carrying any Total Length round-trips.
test('KNXnetIP honors an explicitly supplied Total Length (does not derive over it)', async (): Promise<void> => {
    // CONNECT_REQUEST (0x0205) with a 2-byte body; explicit Total Length = 6 + 2 = 8.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.10', dip: '192.168.0.20', protocol: 17}},
        {id: 'udp', data: {srcport: 50000, dstport: 3671}},
        {id: 'knxnetip', data: {headerLength: 6, protocolVersion: 16, serviceType: 0x0205, totalLength: 8, body: '0201'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const knx: any = Layer(decoded, 'knxnetip').data
    assert.strictEqual(knx.serviceType, 0x0205, 'CONNECT_REQUEST')
    assert.strictEqual(knx.totalLength, 8, 'supplied Total Length honored')
    assert.strictEqual(knx.body, '0201', 'body preserved')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/3671 payload whose first two octets are not the 0x06/0x10 signature must NOT be claimed
// as KNXnet/IP (falls through to raw); and a truncated frame must survive decode without throwing.
test('KNXnetIP rejects a non-signature payload on port 3671, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.10', dip: '192.168.0.20', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 3671}},
        // header length 0x07 / version 0x02 — not the KNXnet/IP 0x06 0x10 signature (no registered
        // content heuristic claims these leading octets either).
        {id: 'raw', data: {data: '0702020100080123456789ab'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'knxnetip'), 'non-signature payload must not be claimed as KNXnet/IP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('knxnetip/search-request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})

// Protocol-specific edge: two KNXnet/IP frames pipelined in one UDP payload. The first frame is bounded
// by its Total Length, so its body does NOT swallow the trailing frame; the trailing bytes fall through
// to raw (the leaf header advances only over its own frame and, since its prev is now knxnetip not udp,
// does not re-match itself). Round-trips byte-for-byte.
test('KNXnetIP pipelining: the first frame is bounded by its Total Length; the trailing frame falls through to raw', async (): Promise<void> => {
    const first: string = '06100201000e0801c0a8000a0e57'   // 14-byte SEARCH_REQUEST
    const second: string = '061005300006'                  // 6-byte ROUTING_INDICATION (header only)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.10', dip: '224.0.23.12', protocol: 17}},
        {id: 'udp', data: {srcport: 3671, dstport: 3671}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'knxnetip', 'raw'])
    const knx: any = Layer(decoded, 'knxnetip').data
    assert.strictEqual(knx.serviceType, 0x0201, 'first is SEARCH_REQUEST')
    assert.strictEqual(knx.body, '0801c0a8000a0e57', 'body bounded by Total Length — trailing frame not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing frame left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
