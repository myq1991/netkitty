import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// GE-SRTP (tcp:18245) READ_SYS_MEMORY request — fixed 56-byte header, byte-perfect round-trip.
test('GESRTP read request: 56-byte header fields + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('gesrtp/read').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'gesrtp'])
    const srtp: any = Layer(decoded, 'gesrtp').data
    assert.strictEqual(srtp.type, 2, 'transmit/request')
    assert.strictEqual(srtp.sequenceNumber, 6, 'sequence number')
    assert.strictEqual(srtp.messageType, 0xc0, 'message-type byte')
    assert.strictEqual(srtp.mailboxDestination, '100e0000', 'mailbox destination verbatim')
    assert.strictEqual(srtp.packetNumber, 1, 'packet 1')
    assert.strictEqual(srtp.totalPacketNumber, 1, 'of 1')
    assert.strictEqual(srtp.serviceRequestCode, 4, 'READ_SYS_MEMORY')
    assert.strictEqual(srtp.segmentSelector, 8, '%R register')
    assert.strictEqual(srtp.memoryOffset, 0, 'LE offset 0 (=%R1)')
    assert.strictEqual(srtp.dataLength, 1, 'LE 1 word')
    assert.strictEqual(srtp.payload, '', 'a read request is just the 56-byte header')
})

// Crafting: a minimal request assembled field-by-field must re-encode byte-identically, and the
// little-endian offset/length must be laid down LSB-first.
test('GESRTP faithfully encodes a crafted read request (little-endian offset/length)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 51234, dstport: 18245}},
        {id: 'gesrtp', data: {type: 2, serviceRequestCode: 4, segmentSelector: 8, memoryOffset: 0x1234, dataLength: 0x0002}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'gesrtp'])
    const srtp: any = Layer(decoded, 'gesrtp').data
    assert.strictEqual(srtp.memoryOffset, 0x1234, 'offset preserved')
    assert.strictEqual(srtp.dataLength, 2, 'length preserved')
    // memoryOffset 0x1234 must sit at bytes 44..45 as 34 12 (LSB first)
    const srtpStart: number = 14 + 20 + 20
    assert.strictEqual(packet.subarray(srtpStart + 44, srtpStart + 46).toString('hex'), '3412', 'offset little-endian LSB-first')
    assert.strictEqual(packet.subarray(srtpStart + 46, srtpStart + 48).toString('hex'), '0200', 'length little-endian LSB-first')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A read response carries data after the 56-byte header; that trailing data is kept verbatim as the
// opaque `payload` hex and round-trips byte-for-byte.
test('GESRTP keeps a response data body as verbatim payload', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.20', dip: '192.0.2.10', protocol: 6}},
        {id: 'tcp', data: {srcport: 18245, dstport: 51234}},
        {id: 'gesrtp', data: {type: 3, serviceRequestCode: 4, payload: 'dead'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'gesrtp'])
    const srtp: any = Layer(decoded, 'gesrtp').data
    assert.strictEqual(srtp.type, 3, 'return')
    assert.strictEqual(srtp.payload, 'dead', 'response data kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a short TCP/18245 payload (< 56-byte header) must NOT be claimed as GE-SRTP (falls through
// to raw); and a truncated GE-SRTP message must survive decode without throwing.
test('GESRTP rejects a sub-header payload on port 18245, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 18245}},
        // only 8 bytes of payload — far short of the 56-byte header
        {id: 'raw', data: {data: '0200060000000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'gesrtp'), 'sub-header payload must not be claimed as GE-SRTP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('gesrtp/read').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 8))
})
