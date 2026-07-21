import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// MQTT (tcp:1883) CONNECT — Fixed Header (type + flags + Remaining Length varint) + Variable Header
// (protocol name "MQTT", level, connect flags, keep-alive) + Payload (client id "test").
test('MQTT CONNECT: fixed header + varint Remaining Length + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('mqtt/connect').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'mqtt'])
    const mqtt: any = Layer(decoded, 'mqtt').data
    assert.strictEqual(mqtt.messageType, 1, 'CONNECT')
    assert.strictEqual(mqtt.flags, 0, 'reserved flags for CONNECT')
    assert.strictEqual(mqtt.remainingLength, 16, 'Variable Header (10) + Payload (6)')
    assert.strictEqual(mqtt.payload, '00044d5154540402003c000474657374', 'variable header + payload verbatim')
})

// A PINGREQ is the smallest possible MQTT packet: type 12, no flags, Remaining Length 0 (a single 0x00
// varint byte), no variable header or payload — the whole frame is the two bytes 0xc0 0x00.
test('MQTT PINGREQ round-trips (type 12, Remaining Length 0, empty payload)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 1883}},
        {id: 'mqtt', data: {messageType: 12, flags: 0, remainingLength: 0}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'mqtt'])
    const mqtt: any = Layer(decoded, 'mqtt').data
    assert.strictEqual(mqtt.messageType, 12, 'PINGREQ')
    assert.strictEqual(mqtt.flags, 0)
    assert.strictEqual(mqtt.remainingLength, 0)
    assert.strictEqual(mqtt.payload, '', 'no variable header or payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A crafted PUBLISH with a multi-byte Remaining Length auto-computed from the payload — confirms the
// varint spans the right number of bytes and the payload lands after it (a 200-byte payload needs a
// 2-byte varint: 0xc8 0x01).
test('MQTT PUBLISH auto-computes a multi-byte Remaining Length varint from the payload', async (): Promise<void> => {
    const payload: string = 'ff'.repeat(200)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 1883}},
        {id: 'mqtt', data: {messageType: 3, flags: 0, payload: payload}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const mqtt: any = Layer(decoded, 'mqtt').data
    assert.strictEqual(mqtt.messageType, 3, 'PUBLISH')
    assert.strictEqual(mqtt.remainingLength, 200, 'derived from the 200-byte payload')
    assert.strictEqual(mqtt.payload, payload, 'payload preserved after the 2-byte varint')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A TCP/1883 payload whose first byte has a zero Message Type nibble (forbidden in MQTT) must fall
// through to raw rather than be claimed as MQTT.
test('MQTT rejects a forbidden Message Type 0 on port 1883 (falls through to raw)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 1883}},
        {id: 'raw', data: {data: '000102030405'}} // message type nibble 0 — not a valid MQTT packet
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'mqtt'), 'message type 0 must not be claimed as MQTT')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
})

test('MQTT truncated mid-frame: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('mqtt/connect').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})
