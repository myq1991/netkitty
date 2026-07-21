import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// OLSR (udp:698, RFC 3626) packet carrying one HELLO message — 4-byte packet header (length + sequence)
// followed by a 12-byte message header (type/Vtime/size/originator/ttl/hop/seq) + verbatim HELLO body.
test('OLSR HELLO: packet header + message header + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('olsr/hello').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'olsr'])
    const olsr: any = Layer(decoded, 'olsr').data
    assert.strictEqual(olsr.packetLength, 28, 'total packet length incl 4-byte header')
    assert.strictEqual(olsr.packetSequenceNumber, 1)
    assert.strictEqual(olsr.messages.length, 1, 'one message')
    const message: any = olsr.messages[0]
    assert.strictEqual(message.messageType, 1, 'HELLO')
    assert.strictEqual(message.vTime, 0x50)
    assert.strictEqual(message.messageSize, 24, 'message octet count incl 12-byte header')
    assert.strictEqual(message.originatorAddress, '192.168.1.1')
    assert.strictEqual(message.ttl, 1)
    assert.strictEqual(message.hopCount, 0)
    assert.strictEqual(message.messageSeqNo, 5)
    assert.strictEqual(message.body, '000005060a000008c0a80102', 'HELLO body kept verbatim')
})

// Crafting: a TC (type 2) message with the Message Size and Packet Length both auto-derived from the
// actual bytes — the minimal well-formed OLSR packet must re-encode byte-identically.
test('OLSR faithfully encodes a crafted TC and auto-derives Message Size + Packet Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '02:00:00:00:00:02', smac: '02:00:00:00:00:01', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.255', protocol: 17}},
        {id: 'udp', data: {srcport: 698, dstport: 698}},
        {id: 'olsr', data: {packetSequenceNumber: 7, messages: [
            {messageType: 2, vTime: 0x50, originatorAddress: '192.0.2.1', ttl: 255, hopCount: 0, messageSeqNo: 9, body: '0000c0a80102'}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'olsr'])
    const olsr: any = Layer(decoded, 'olsr').data
    assert.strictEqual(olsr.messages[0].messageType, 2, 'TC')
    assert.strictEqual(olsr.messages[0].messageSize, 18, 'derived Message Size = 12 header + 6 body')
    assert.strictEqual(olsr.packetLength, 22, 'derived Packet Length = 4 header + 18 message')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted packet supplies explicit Packet Length and Message Size — both must be
// honored verbatim (not overwritten by the derived value) so a packet carrying any length round-trips.
test('OLSR honors an explicitly supplied Packet Length and Message Size', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '02:00:00:00:00:02', smac: '02:00:00:00:00:01', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.255', protocol: 17}},
        {id: 'udp', data: {srcport: 698, dstport: 698}},
        {id: 'olsr', data: {packetLength: 20, packetSequenceNumber: 3, messages: [
            {messageType: 3, vTime: 0x40, messageSize: 16, originatorAddress: '192.0.2.9', ttl: 8, hopCount: 1, messageSeqNo: 2, body: 'c0a80102'}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const olsr: any = Layer(decoded, 'olsr').data
    assert.strictEqual(olsr.messages[0].messageType, 3, 'MID')
    assert.strictEqual(olsr.messages[0].messageSize, 16, 'supplied Message Size honored')
    assert.strictEqual(olsr.packetLength, 20, 'supplied Packet Length honored')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/698 payload shorter than the 4-byte packet header must NOT be claimed as OLSR (falls
// through to raw); and a truncated OLSR packet must survive decode without throwing.
test('OLSR rejects a sub-header UDP/698 payload, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '02:00:00:00:00:02', smac: '02:00:00:00:00:01', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 698, dstport: 698}},
        // only 2 bytes — shorter than the 4-byte OLSR packet header
        {id: 'raw', data: {data: '0001'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'olsr'), 'sub-header payload must not be claimed as OLSR')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('olsr/hello').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})

// Protocol-specific edge: a complete HELLO message followed by 6 trailing bytes too short to be another
// message. The message walk is bounded by each Message Size and stops when the remaining bytes cannot
// hold a 12-byte message header, so the trailing bytes fall through to raw. Round-trips byte-for-byte.
test('OLSR message walk is bounded: a trailing partial message falls through to raw', async (): Promise<void> => {
    // packetLength 34 = 4 header + 24-byte HELLO + 6 trailing bytes; the trailing 6 bytes cannot form a message.
    const payload: string = '00220001' + '01500018c0a8010101000005000005060a000008c0a80102' + 'aabbccddeeff'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '02:00:00:00:00:02', smac: '02:00:00:00:00:01', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.255', protocol: 17}},
        {id: 'udp', data: {srcport: 698, dstport: 698}},
        {id: 'raw', data: {data: payload}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'olsr', 'raw'])
    const olsr: any = Layer(decoded, 'olsr').data
    assert.strictEqual(olsr.messages.length, 1, 'only the complete message is consumed')
    assert.strictEqual(olsr.messages[0].messageType, 1, 'HELLO')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, 'aabbccddeeff', 'trailing partial message left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
