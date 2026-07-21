import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// MongoDB Wire Protocol (tcp:27017) OP_MSG — 16-byte little-endian standard message header
// (messageLength/requestID/responseTo/opCode) + OP_MSG body (flagBits + Kind 0 body section + BSON).
test('MongoDB OP_MSG: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('mongodb/op-msg').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'mongodb'])
    const mongo: any = Layer(decoded, 'mongodb').data
    assert.strictEqual(mongo.messageLength, 36, 'whole-message length incl 16-byte header')
    assert.strictEqual(mongo.requestID, 1, 'little-endian request id')
    assert.strictEqual(mongo.responseTo, 0, 'unsolicited request')
    assert.strictEqual(mongo.opCode, 2013, 'OP_MSG')
    // flagBits 0x00000000 + section kind 0 + BSON {ping:1(int32)}
    assert.strictEqual(mongo.body, '00000000000f0000001070696e67000100000000', 'OP_MSG body verbatim')
})

// Crafting: a minimal OP_QUERY (legacy opCode 2004) with the messageLength auto-computed from the body —
// confirm the little-endian header lands correctly and the message round-trips byte-for-byte.
test('MongoDB faithfully encodes a crafted OP_QUERY and auto-computes the messageLength', async (): Promise<void> => {
    // OP_QUERY body: flags(0) + b"admin.$cmd\0" + numberToSkip 0 + numberToReturn 1 + BSON {isMaster:1}
    const body: string = '00000000' + '61646d696e2e24636d6400' + '00000000' + '01000000'
        + '13000000' + '10' + '69734d617374657200' + '01000000' + '00'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 27017}},
        {id: 'mongodb', data: {requestID: 0x11223344, responseTo: 0, opCode: 2004, body}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'mongodb'])
    const mongo: any = Layer(decoded, 'mongodb').data
    assert.strictEqual(mongo.opCode, 2004, 'OP_QUERY')
    assert.strictEqual(mongo.requestID, 0x11223344, 'little-endian request id')
    assert.strictEqual(mongo.messageLength, 16 + body.length / 2, 'auto-computed length = 16 + body bytes')
    assert.strictEqual(mongo.body, body, 'OP_QUERY body verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive messageLength: a crafted OP_REPLY supplies an explicit (wrong) messageLength — it
// must be honored verbatim (not overwritten by the derived value) so a message with any length
// round-trips. The body is bounded by the supplied messageLength.
test('MongoDB honors an explicitly supplied messageLength (does not derive over it)', async (): Promise<void> => {
    // OP_REPLY (opCode 1) body kept short (8 bytes); supply messageLength = 16 + 8 = 24 explicitly.
    const body: string = '0000000000000000'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.2', dip: '10.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 27017, dstport: 40000}},
        {id: 'mongodb', data: {messageLength: 24, requestID: 7, responseTo: 3, opCode: 1, body}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const mongo: any = Layer(decoded, 'mongodb').data
    assert.strictEqual(mongo.opCode, 1, 'OP_REPLY')
    assert.strictEqual(mongo.responseTo, 3, 'reply ties back to request 3')
    assert.strictEqual(mongo.messageLength, 24, 'supplied messageLength honored')
    assert.strictEqual(mongo.body, body, 'body bounded by supplied messageLength')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/27017 payload too short to hold the 16-byte header must NOT be claimed as MongoDB
// (falls through to raw); and a truncated MongoDB message must survive decode without throwing.
test('MongoDB requires the full 16-byte header, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 27017}},
        // 6 bytes — fewer than the 16-byte standard message header; not signed-magic, unambiguous raw
        {id: 'raw', data: {data: '2400000001'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'mongodb'), 'a sub-header payload must not be claimed as MongoDB')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('mongodb/op-msg').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})

// Protocol-specific edge: two MongoDB messages pipelined in one TCP segment. The first message is
// bounded by its messageLength, so its body does NOT swallow the trailing message; the trailing bytes
// fall through to raw (match() gates on the previous layer being TCP, so a leaf header advances only
// over its own message and does not re-match itself — matching the length-bounded-TCP-payload / BGP
// precedent). Both directions round-trip byte-for-byte.
test('MongoDB pipelining: the first message is bounded by its messageLength; the trailing message falls through to raw', async (): Promise<void> => {
    // first: OP_MSG, messageLength 36, body 20 bytes; second: OP_MSG, messageLength 21, body 5 bytes.
    const firstBody: string = '00000000000f0000001070696e67000100000000'      // 20 bytes
    const first: string = '24000000' + '01000000' + '00000000' + 'dd070000' + firstBody
    const second: string = '15000000' + '02000000' + '00000000' + 'dd070000' + '0000000000'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 27017}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'mongodb', 'raw'])
    const firstMongo: any = Layer(decoded, 'mongodb').data
    assert.strictEqual(firstMongo.messageLength, 36, 'first message length')
    assert.strictEqual(firstMongo.body, firstBody, 'first body bounded by its messageLength — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing message left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
