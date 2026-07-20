import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// MQTT-SN v1.2 (udp:1883) CONNECT — 1-octet Length + Message Type + type-specific body.
test('MQTT-SN CONNECT: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('mqttsn/connect').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'mqttsn'])
    const mqttsn: any = Layer(decoded, 'mqttsn').data
    assert.strictEqual(mqttsn.length, 12, 'whole-message length incl the 1-octet Length + Message Type')
    assert.strictEqual(mqttsn.msgType, 0x04, 'CONNECT')
    assert.strictEqual(mqttsn.body, '0401000a636c69656e74', 'flags 0x04, protocol id 1, keep-alive 10, client id "client"')
})

// Crafting: a CONNACK (msgType 0x05, 1-byte return-code body) with the Length auto-derived from the body
// — the minimal 1-octet-Length message must re-encode byte-identically.
test('MQTT-SN faithfully encodes a crafted CONNACK and auto-derives the 1-octet Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.2', dip: '10.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 1883, dstport: 50000}},
        {id: 'mqttsn', data: {msgType: 0x05, body: '00'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'mqttsn'])
    const mqttsn: any = Layer(decoded, 'mqttsn').data
    assert.strictEqual(mqttsn.msgType, 0x05, 'CONNACK')
    assert.strictEqual(mqttsn.length, 3, 'auto-derived Length = Length(1) + Message Type(1) + 1-byte body')
    assert.strictEqual(mqttsn.body, '00', 'accepted return code')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted message supplies an explicit Length — it must be honored verbatim
// (not overwritten by the derived value) so a message carrying any Length round-trips.
test('MQTT-SN honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 50000, dstport: 1883}},
        {id: 'mqttsn', data: {length: 99, msgType: 0x0c, body: 'aabb'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const mqttsn: any = Layer(decoded, 'mqttsn').data
    assert.strictEqual(mqttsn.msgType, 0x0c, 'PUBLISH')
    assert.strictEqual(mqttsn.length, 99, 'supplied Length honored')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// The 3-octet escape Length form (0x01 + big-endian uint16) is chosen automatically when the whole
// message exceeds 255 octets, and round-trips byte-for-byte.
test('MQTT-SN uses the 3-octet escape Length form for a message > 255 octets', async (): Promise<void> => {
    const body: string = 'ab'.repeat(300)                            // 300-byte body => length 304 (escape form)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 50000, dstport: 1883}},
        {id: 'mqttsn', data: {msgType: 0x0c, body: body}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const mqttsn: any = Layer(decoded, 'mqttsn').data
    assert.strictEqual(mqttsn.length, 304, 'derived Length = Length(3) + Message Type(1) + 300-byte body')
    assert.strictEqual(mqttsn.body, body, 'body preserved across the escape-form Length')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/1883 payload too short to hold even the Length + Message Type (1 byte) must NOT be
// claimed as MQTT-SN (falls through to raw); and a truncated MQTT-SN datagram survives decode.
test('MQTT-SN rejects an under-length UDP/1883 payload, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 50000, dstport: 1883}},
        {id: 'raw', data: {data: 'ff'}}                              // a single payload octet
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'mqttsn'), 'a 1-octet payload must not be claimed as MQTT-SN')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('mqttsn/connect').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})
