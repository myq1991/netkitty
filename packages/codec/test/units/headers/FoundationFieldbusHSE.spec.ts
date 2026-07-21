import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// FOUNDATION Fieldbus HSE (IEC 61158, udp/tcp:1089-1091) — an FDA (Field Device Access) message: a
// 12-byte FDA Message Header (version / options / protocol-id-and-type / service / FDA address /
// message length) followed by the service body, kept verbatim and bounded by Message Length.
test('FF-HSE over UDP: FDA header fields + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ffhse/fda-udp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ffhse'])
    const ff: any = Layer(decoded, 'ffhse').data
    assert.strictEqual(ff.version, 1, 'FDA message version')
    assert.strictEqual(ff.options, 0x00, 'options: no trailer fields, no pad')
    assert.strictEqual(ff.protocolAndType, 0x88, 'protocol id and confirmed msg type')
    assert.strictEqual(ff.service, 0x04, 'service octet')
    assert.strictEqual(ff.fdaAddress, '00000001', 'FDA address')
    assert.strictEqual(ff.messageLength, 20, 'total FDA message length (12-byte header + 8-byte body)')
    assert.strictEqual(ff.body, '0000100000000001', 'service body kept verbatim')
})

// Identical FDA layout over TCP (no record/length prefix — Message Length is the sole delimiter).
test('FF-HSE over TCP: FDA message round-trips byte-for-byte', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ffhse/fda-tcp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'ffhse'])
    const ff: any = Layer(decoded, 'ffhse').data
    assert.strictEqual(ff.version, 1, 'FDA message version')
    assert.strictEqual(ff.messageLength, 20, 'total FDA message length')
    assert.strictEqual(ff.body, '0000100000000002', 'service body kept verbatim')
})

// Crafting: a minimal FDA message with the Message Length auto-derived from the (12-byte header + body).
test('FF-HSE faithfully encodes a crafted FDA message and auto-derives Message Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 49152, dstport: 1091}},
        {id: 'ffhse', data: {version: 1, options: 0, protocolAndType: 0x88, service: 0x04, fdaAddress: '00000001', body: 'deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ffhse'])
    const ff: any = Layer(decoded, 'ffhse').data
    assert.strictEqual(ff.messageLength, 16, 'auto-derived Message Length = 12 header + 4 body')
    assert.strictEqual(ff.body, 'deadbeef', 'body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted message supplies an explicit (lying) Message Length — it must be honored
// verbatim (not overwritten by the derived value) so a message carrying any Message Length round-trips.
test('FF-HSE honors an explicitly supplied Message Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 49152, dstport: 1089}},
        // messageLength lies (99) while the real message is 12 + 4 = 16 bytes; honored verbatim.
        {id: 'ffhse', data: {version: 2, options: 0, protocolAndType: 0x88, service: 0x81, fdaAddress: 'cafebabe', messageLength: 99, body: '01020304'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const ff: any = Layer(decoded, 'ffhse').data
    assert.strictEqual(ff.messageLength, 99, 'supplied Message Length honored (even though it lies)')
    assert.strictEqual(ff.service, 0x81, 'confirmed flag + service id round-trip')
    // Message Length lies past the captured UDP payload, so body is clamped to the payload, not read OOB.
    assert.strictEqual(ff.body, '01020304', 'body clamped to the transport payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/1089 payload shorter than the 12-byte FDA header must NOT be claimed as FF-HSE (falls
// through to raw); and a truncated FDA message must survive decode without throwing.
test('FF-HSE rejects a sub-header payload on port 1089, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 49152, dstport: 1089}},
        // 11 bytes — one short of the 12-byte FDA Message Header
        {id: 'raw', data: {data: 'ffffffffffffffffffffff'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'ffhse'), 'sub-header payload must not be claimed as FF-HSE')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('ffhse/fda-udp').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 3))
})

// Protocol-specific edge: two FDA messages pipelined in one UDP datagram. The first is bounded by its
// Message Length, so its body does NOT swallow the trailing message; the trailing bytes fall through to
// raw (a leaf header advances only over its own message and does not re-match itself — same precedent as
// BGP). Round-trips byte-for-byte.
test('FF-HSE pipelining: the first message is bounded by its Message Length; the trailing message falls through to raw', async (): Promise<void> => {
    const msg1: string = '010088040000000100000014' + '0000100000000001'   // 20-byte FDA message
    const msg2: string = '010088040000000200000014' + '00001000000000ff'   // trailing 20-byte FDA message
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 49152, dstport: 1089}},
        {id: 'raw', data: {data: msg1 + msg2}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ffhse', 'raw'])
    const ff: any = Layer(decoded, 'ffhse').data
    assert.strictEqual(ff.messageLength, 20, 'first message length')
    assert.strictEqual(ff.body, '0000100000000001', 'first body bounded by its Message Length — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, msg2, 'trailing FDA message left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
