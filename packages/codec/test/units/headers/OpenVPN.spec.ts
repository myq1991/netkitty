import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// A control packet tail: 8-byte session id + message-packet-id array length 0 + 4-byte message packet-id.
const CONTROL_BODY: string = '01020304050607080000000000'

// OpenVPN over UDP (udp:1194) — P_CONTROL_HARD_RESET_CLIENT_V2. The packet is the whole datagram (no
// length prefix): opcode/key-id split, then the control tail kept verbatim; byte-perfect round-trip.
test('OpenVPN UDP: opcode/key-id split + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('openvpn/hard-reset-client-v2-udp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'openvpn'])
    const ovpn: any = Layer(decoded, 'openvpn').data
    assert.strictEqual(ovpn.opcode, 7, 'P_CONTROL_HARD_RESET_CLIENT_V2')
    assert.strictEqual(ovpn.keyId, 0, 'key id')
    assert.strictEqual(ovpn.body, CONTROL_BODY, 'session id + ack array + message packet-id kept verbatim')
    assert.strictEqual(ovpn.length, undefined, 'no length prefix over UDP')
})

// OpenVPN over TCP (tcp:1194) — same control packet behind the 2-byte big-endian record length prefix.
test('OpenVPN TCP: length prefix + opcode/key-id + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('openvpn/hard-reset-client-v2-tcp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'openvpn'])
    const ovpn: any = Layer(decoded, 'openvpn').data
    assert.strictEqual(ovpn.length, 14, 'record length = OpenVPN packet bytes (1 octet + 13 body)')
    assert.strictEqual(ovpn.opcode, 7, 'P_CONTROL_HARD_RESET_CLIENT_V2')
    assert.strictEqual(ovpn.keyId, 0, 'key id')
    assert.strictEqual(ovpn.body, CONTROL_BODY, 'control tail kept verbatim')
})

// honor-else-derive over TCP: a crafted packet with no length supplied — it is derived as the encoded
// OpenVPN packet length; both directions round-trip byte-for-byte.
test('OpenVPN TCP derives the record length prefix when not supplied', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 1194}},
        {id: 'openvpn', data: {opcode: 5, keyId: 2, body: 'aabbccdd'}} // P_CONTROL_V1, length auto-derived
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'openvpn'])
    const ovpn: any = Layer(decoded, 'openvpn').data
    assert.strictEqual(ovpn.opcode, 5, 'P_CONTROL_V1')
    assert.strictEqual(ovpn.keyId, 2, 'key id honored')
    assert.strictEqual(ovpn.length, 5, 'derived length = 1 opcode octet + 4 body bytes')
    assert.strictEqual(ovpn.body, 'aabbccdd', 'body kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted TCP packet supplies an explicit (lying) length — it must be honored
// verbatim, not overwritten by the derived value. A P_DATA_V2 (opcode 9) carries an opaque payload.
test('OpenVPN TCP honors an explicitly supplied length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 1194, dstport: 40000}},
        {id: 'openvpn', data: {length: 9, opcode: 9, keyId: 1, body: '00c0ffee'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const ovpn: any = Layer(decoded, 'openvpn').data
    assert.strictEqual(ovpn.length, 9, 'supplied length honored (a crafted frame may lie)')
    assert.strictEqual(ovpn.opcode, 9, 'P_DATA_V2')
    assert.strictEqual(ovpn.keyId, 1, 'key id')
    assert.strictEqual(ovpn.body, '00c0ffee', 'payload kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a crafted UDP/1194 datagram bounds the OpenVPN packet by udp.length − 8 so trailing UDP
// padding is not swallowed; and a truncated OpenVPN packet must survive decode without throwing.
test('OpenVPN UDP is bounded by the UDP length, and truncation survives', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('openvpn/hard-reset-client-v2-udp').buffer)
    const ovpn: any = Layer(decoded, 'openvpn').data
    assert.strictEqual(ovpn.opcode, 7, 'decoded opcode')

    const full: Buffer = LoadPacket('openvpn/hard-reset-client-v2-tcp').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
    await AssertDecodeSurvives(LoadPacket('openvpn/hard-reset-client-v2-udp').buffer.subarray(0, 43))
})
