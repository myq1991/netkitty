import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// A real RabbitMQ Connection.Start METHOD frame (tcp:5672) — type/channel/length/payload/frameEnd —
// round-trips byte-for-byte and decodes to the expected frame fields.
test('AMQP real Connection.Start METHOD frame: byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('amqp/method').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'amqp'])
    const amqp: any = Layer(decoded, 'amqp').data
    assert.strictEqual(amqp.isProtocolHeader, false, 'a frame, not the protocol-header handshake')
    assert.strictEqual(amqp.type, 1, 'METHOD frame')
    assert.strictEqual(amqp.channel, 0)
    assert.strictEqual(amqp.length, 514, 'payload length')
    assert.strictEqual(amqp.frameEnd, 0xce, 'frame-end marker preserved')
    // Payload is kept verbatim; it begins with class 10 (Connection) method 10 (Start).
    assert.strictEqual(amqp.payload.length, 514 * 2, 'payload hex is length octets')
    assert.strictEqual(amqp.payload.slice(0, 8), '000a000a', 'class 0x000a method 0x000a')
})

// Crafting a METHOD frame (type 1) with the Length auto-computed from the payload — confirm the frame
// re-encodes byte-identically and the 0xCE frame-end octet is preserved.
test('AMQP crafted METHOD frame re-encodes byte-identically (frameEnd 0xCE preserved)', async (): Promise<void> => {
    // A real Connection.Tune method payload: class 10, method 30, channel-max 2047, frame-max 131072,
    // heartbeat 60.
    const tunePayload: string = '000a001e07ff0002000000 3c'.replace(/\s/g, '')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 5672, dstport: 40000}},
        {id: 'amqp', data: {isProtocolHeader: false, type: 1, channel: 0, payload: tunePayload}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'amqp'])
    const amqp: any = Layer(decoded, 'amqp').data
    assert.strictEqual(amqp.type, 1)
    assert.strictEqual(amqp.length, 12, 'Length auto-computed from the 12-byte payload')
    assert.strictEqual(amqp.frameEnd, 0xce, 'default frame-end marker')
    assert.strictEqual(amqp.payload, tunePayload)
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// The 8-byte connection-start protocol header ("AMQP" + 0 0 9 1) decodes as isProtocolHeader and
// round-trips byte-perfect.
test('AMQP protocol-header handshake decodes as isProtocolHeader and round-trips', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 5672}},
        {id: 'amqp', data: {isProtocolHeader: true, protocol: 'AMQP', protocolId: 0, versionMajor: 0, versionMinor: 9, versionRevision: 1}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'amqp'])
    const amqp: any = Layer(decoded, 'amqp').data
    assert.strictEqual(amqp.isProtocolHeader, true)
    assert.strictEqual(amqp.protocol, 'AMQP')
    assert.strictEqual(amqp.versionMinor, 9)
    assert.strictEqual(amqp.versionRevision, 1)
    // The 8-byte protocol header on the wire: "AMQP" 00 00 09 01.
    const tcpPayload: string = Layer(decoded, 'tcp') && packet.toString('hex').slice(-16)
    assert.strictEqual(tcpPayload, '414d515000000901', 'literal AMQP\\0\\0\\9\\1 on the wire')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Length honor-else-derive + bounding: two AMQP frames back to back. The first frame's Length bounds its
// payload so it does NOT swallow the second frame; and because match() requires the previous layer to be
// TCP (like ENIP/Modbus), the pipelined second frame is left to the codec's recursion → raw.
test('AMQP length bounds the frame; the pipelined trailing frame falls to raw', async (): Promise<void> => {
    // Frame A: METHOD (type 1, channel 0, payload 'aabb', Length derived = 2). Frame B: a second frame
    // that must NOT be absorbed into frame A's payload.
    const frameA: string = '01' + '0000' + '00000002' + 'aabb' + 'ce'
    const frameB: string = '08' + '0000' + '00000000' + 'ce'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 5672, dstport: 40000}},
        {id: 'raw', data: {data: frameA + frameB}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const amqps: CodecDecodeResult[] = decoded.filter((l: CodecDecodeResult): boolean => l.id === 'amqp')
    assert.strictEqual(amqps.length, 1, 'only the first frame is claimed as AMQP')
    assert.strictEqual((amqps[0].data as any).type, 1, 'first frame is the METHOD')
    assert.strictEqual((amqps[0].data as any).length, 2, 'Length derived from the 2-byte payload')
    assert.strictEqual((amqps[0].data as any).payload, 'aabb', 'payload bounded — frame B not swallowed')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw', 'the trailing pipelined frame falls to raw')
    assert.strictEqual((decoded[decoded.length - 1].data as any).data, frameB, 'raw carries the untouched second frame')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A TCP/5672 payload that is neither the "AMQP" literal nor a known frame type must fall through to raw;
// a truncated frame must not crash the decoder.
test('AMQP rejects a non-AMQP payload on port 5672; truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 5672}},
        {id: 'raw', data: {data: '99000000000002aabbce'}} // first byte 0x99 is not a valid frame type
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'amqp'), 'bad first byte must not be claimed as AMQP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
    // Truncated real frame: decode must survive without throwing.
    const full: Buffer = LoadPacket('amqp/method').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 40))
})
