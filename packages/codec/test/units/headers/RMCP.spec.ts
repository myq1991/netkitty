import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// ASF RMCP Presence Ping (ASF 2.0 / DSP0136) on UDP 623: a 4-byte RMCP header (version/reserved/
// sequence/class) followed by an ASF message (IANA enterprise 4542, type 0x80 = ping).
test('RMCP ASF Presence Ping: header + ASF message decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rmcp/asf-presence-ping').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rmcp'])
    const rmcp: any = Layer(decoded, 'rmcp').data
    assert.strictEqual(rmcp.version, 6, 'RMCP 1.0')
    assert.strictEqual(rmcp.sequence, 255, 'no ACK requested')
    assert.strictEqual(rmcp.messageClass.ack, false, 'a normal (non-ACK) message')
    assert.strictEqual(rmcp.messageClass.class, 6, 'ASF class')
    assert.strictEqual(rmcp.asf.enterprise, 4542, 'ASF IANA enterprise number')
    assert.strictEqual(rmcp.asf.type, 0x80, 'Presence Ping')
    assert.strictEqual(rmcp.asf.dataLength, 0)
    assert.strictEqual(rmcp.rawBody, '', 'ASF is decoded structurally, nothing left as raw body')
})

// A non-ASF class (IPMI, class 7) carries a session-wrapped message, NOT an ASF frame. The codec must
// keep it verbatim (rawBody) and must NOT try to read an ASF header out of it.
test('RMCP IPMI class keeps its session payload verbatim (no ASF mis-decode)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 623}},
        {id: 'rmcp', data: {
            version: 6, reserved: '00', sequence: 0,
            messageClass: {ack: false, reserved: 0, class: 7},
            rawBody: '06c0000011be0000000102' // an opaque IPMI session wrapper
        }}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rmcp'])
    const rmcp: any = Layer(decoded, 'rmcp').data
    assert.strictEqual(rmcp.messageClass.class, 7, 'IPMI class')
    assert.strictEqual(rmcp.rawBody, '06c0000011be0000000102', 'session payload preserved verbatim')
    assert.ok(rmcp.asf === undefined || rmcp.asf.enterprise === undefined, 'ASF header not read out of a non-ASF payload')
})

// Crafting: build an ASF Presence Pong (type 0x40) carrying data, with the ACK bit set — the codec is a
// faithful executor and must re-emit exactly what was asked for, byte-for-byte.
test('RMCP faithfully encodes a crafted ASF Presence Pong with the ACK bit set', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.2', dip: '10.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 623, dstport: 40000}},
        {id: 'rmcp', data: {
            version: 6, reserved: '00', sequence: 255,
            messageClass: {ack: true, reserved: 0, class: 6},
            asf: {enterprise: 4542, type: 0x40, tag: 1, reserved: '00', dataLength: 4, data: 'deadbeef'}
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rmcp'])
    const rmcp: any = Layer(decoded, 'rmcp').data
    assert.strictEqual(rmcp.messageClass.ack, true, 'ACK flag re-emitted')
    assert.strictEqual(rmcp.asf.type, 0x40, 'Presence Pong')
    assert.strictEqual(rmcp.asf.data, 'deadbeef', 'ASF data preserved')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Regression: a bare 4-byte ASF-class RMCP ACK (class byte 0x86, no ASF body) must NOT acquire a
// fabricated 8-byte ASF header on re-encode. The class-6/empty-payload case falls in the gap between
// the ASF path (needs >=12 bytes) and the rawBody path (needs >4 bytes), so the encoder must recognize
// that no ASF message was present.
test('RMCP bare 4-byte ASF-class ACK round-trips byte-perfect (no phantom ASF bytes)', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rmcp/asf-ack').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rmcp'])
    const rmcp: any = Layer(decoded, 'rmcp').data
    assert.strictEqual(rmcp.messageClass.ack, true, 'ACK bit set')
    assert.strictEqual(rmcp.messageClass.class, 6, 'ASF class')
    assert.strictEqual(rmcp.rawBody, '', 'no body')
    assert.ok(rmcp.asf === undefined || rmcp.asf.enterprise === undefined, 'no ASF message present')
})

test('RMCP truncated mid-header: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('rmcp/asf-presence-ping').buffer
    // Chop into the RMCP header (keep eth+ip+udp, drop most of the RMCP payload).
    await AssertDecodeSurvives(full.subarray(0, 44))
})

// A UDP/623 datagram too short to hold even the 4-byte RMCP header must fall through to raw rather than
// claim an un-decodable layer.
test('RMCP too-short UDP/623 payload falls through to RawData', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 623}},
        {id: 'raw', data: {data: '0600'}} // only 2 bytes on port 623
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'rmcp'), 'must not claim a 2-byte payload as RMCP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw', 'the short payload stays raw')
})
