import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Real MySQL 8.0.46 server greeting (tcp:3306, seq 0) — 4-byte packet header (3-byte LE length + seq id)
// + verbatim handshake payload. The payload begins with protocol version 0x0a.
const GREETING_PAYLOAD: string = '0a382e302e343600090000004d3f065e4228535e00ffffff0200ffdf1500000000000000000000350d3c2704417b0949772b480063616368696e675f736861325f70617373776f726400'

test('MySQL greeting: packet header + verbatim payload + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('mysql/greeting').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'mysql'])
    const mysql: any = Layer(decoded, 'mysql').data
    assert.strictEqual(mysql.sequenceId, 0, 'greeting is sequence 0')
    assert.strictEqual(mysql.payloadLength, 74, '3-byte little-endian length (4a 00 00)')
    assert.strictEqual(mysql.payload, GREETING_PAYLOAD, 'payload kept verbatim; begins with protocol version 0x0a')
})

// Craft a client COM_QUERY command whose payload is exactly 16 bytes (0x03 + "SELECT @@GLOBAL"), let the
// length auto-compute, and confirm the 3-byte length lands on the wire LITTLE-ENDIAN (0x10 → 10 00 00).
test('MySQL crafts a command with an auto-computed little-endian length', async (): Promise<void> => {
    const commandPayload: string = '0353454c454354204040474c4f42414c' // 0x03 COM_QUERY + "SELECT @@GLOBAL" (16 bytes)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 3306}},
        {id: 'mysql', data: {sequenceId: 0, payload: commandPayload}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'mysql'])
    const mysql: any = Layer(decoded, 'mysql').data
    assert.strictEqual(mysql.payloadLength, 16, 'auto-computed from the 16-byte payload')
    assert.strictEqual(mysql.sequenceId, 0)
    assert.strictEqual(mysql.payload, commandPayload)
    // The 3-byte length is little-endian: value 0x10 → bytes 10 00 00 (low byte first), then seq id 00.
    assert.ok(packet.toString('hex').includes('10000000' + commandPayload), 'little-endian length 10 00 00 on the wire')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect re-encode')
})

// A pipelined second MySQL frame in the same segment: the first frame's payload is bounded by its length
// field (honored, not derived), and the trailing second frame falls through to raw. Byte-perfect.
test('MySQL bounds the payload by the length field; a pipelined 2nd frame → raw', async (): Promise<void> => {
    const frame1: string = '030000' + '00' + 'aabbcc'   // length 3 (LE), seq 0, payload aabbcc
    const frame2: string = '020000' + '01' + 'ddee'      // pipelined: length 2 (LE), seq 1, payload ddee
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 3306}},
        {id: 'raw', data: {data: frame1 + frame2}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'mysql', 'raw'])
    const mysql: any = Layer(decoded, 'mysql').data
    assert.strictEqual(mysql.payloadLength, 3, 'length field honored')
    assert.strictEqual(mysql.payload, 'aabbcc', 'payload bounded to payloadLength bytes')
    assert.strictEqual(Layer(decoded, 'raw').data.data, frame2, 'the pipelined 2nd frame is left to raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Truncation survives, and the port-bucket confinement: a MySQL-looking payload on a non-3306 port is not
// claimed as MySQL (it falls through to raw).
test('MySQL: truncation survives; a MySQL-looking payload off port 3306 → raw', async (): Promise<void> => {
    const full: Buffer = LoadPacket('mysql/greeting').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 5))

    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 9999}},
        {id: 'raw', data: {data: '030000000353454c454354204040474c4f42414c'}} // a plausible MySQL frame, but on port 9999
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'mysql'), 'off-bucket traffic must not be claimed as MySQL')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
})

// A 3-byte length near the 0xFFFFFF maximum round-trips exactly and lands little-endian (0xFFFFFE → fe ff
// ff), proving no sign issue at the top of the 24-bit range.
test('MySQL: a 3-byte length near 0xFFFFFF round-trips little-endian', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 3306}},
        {id: 'mysql', data: {payloadLength: 0xfffffe, sequenceId: 5, payload: 'aabb'}}
    ])
    // Wire: 3-byte length 0xFFFFFE little-endian = fe ff ff, then seq id 05, then the payload aabb.
    assert.ok(packet.toString('hex').includes('feffff05aabb'), 'little-endian fe ff ff on the wire (no sign issue)')
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const mysql: any = Layer(decoded, 'mysql').data
    assert.strictEqual(mysql.payloadLength, 16777214, '0xFFFFFE decodes back exactly (unsigned)')
    assert.strictEqual(mysql.sequenceId, 5)
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
