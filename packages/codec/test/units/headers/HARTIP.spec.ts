import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// HART-IP (udp:5094) Session Initiate Request — 8-byte header + 5-byte HART PDU payload.
test('HARTIP UDP: header + payload + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('hartip/session-init-udp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'hartip'])
    const hip: any = Layer(decoded, 'hartip').data
    assert.strictEqual(hip.version, 1, 'HART-IP version 1')
    assert.strictEqual(hip.messageType, 0, 'Request')
    assert.strictEqual(hip.messageId, 0, 'Session Initiate')
    assert.strictEqual(hip.status, 0, 'status 0 on a request')
    assert.strictEqual(hip.sequenceNumber, 1, 'sequence number')
    assert.strictEqual(hip.byteCount, 13, 'total message length incl 8-byte header')
    assert.strictEqual(hip.payload, '010000ea60', 'host type primary + inactivity timer 60000ms')
})

// Crafting over TCP (tcp:5094) — HART-IP uses the same 8-byte header on TCP (no record-marking prefix);
// a Token-Passing PDU (message id 3) with an auto-computed Byte Count must re-encode byte-identically.
test('HARTIP faithfully encodes a crafted TCP Token-Passing PDU and auto-computes the Byte Count', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 5094}},
        {id: 'hartip', data: {version: 1, messageType: 0, messageId: 3, status: 0, sequenceNumber: 5, payload: 'aabbccdd'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'hartip'])
    const hip: any = Layer(decoded, 'hartip').data
    assert.strictEqual(hip.messageId, 3, 'Token-Passing PDU')
    assert.strictEqual(hip.byteCount, 12, 'auto-computed Byte Count = 8 header + 4 payload')
    assert.strictEqual(hip.payload, 'aabbccdd', 'PDU kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Byte Count: a crafted Keep Alive supplies an explicit Byte Count — it must be
// honored verbatim (not overwritten by the derived value) so a message that carries any length round-trips.
test('HARTIP honors an explicitly supplied Byte Count (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.20', dip: '192.0.2.10', protocol: 17}},
        {id: 'udp', data: {srcport: 5094, dstport: 40000}},
        // Keep Alive (message id 2), Response (message type 1); Byte Count deliberately says 12 while the
        // payload is only 2 bytes (a crafted message may lie about its length).
        {id: 'hartip', data: {version: 1, messageType: 1, messageId: 2, status: 0, sequenceNumber: 7, byteCount: 12, payload: '1122'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const hip: any = Layer(decoded, 'hartip').data
    assert.strictEqual(hip.messageType, 1, 'Response')
    assert.strictEqual(hip.messageId, 2, 'Keep Alive')
    assert.strictEqual(hip.byteCount, 12, 'supplied Byte Count honored')
    assert.strictEqual(hip.payload, '1122', 'payload bounded by the transport payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/5094 payload whose Version is not 1 must NOT be claimed as HART-IP (falls through to
// raw); and a truncated HART-IP message must survive decode without throwing.
test('HARTIP rejects a non-1 Version on port 5094, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 5094}},
        // version byte 0x09 (not 1) — not the HART-IP signature
        {id: 'raw', data: {data: '0900000000000009aabbcc'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'hartip'), 'non-1 Version must not be claimed as HART-IP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('hartip/session-init-udp').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 3))
})

// Regression (was a decode→encode throw): a crafted message with a Byte Count below the 8-byte header
// (0..7) and out-of-range messageType/messageId must decode AND re-encode without throwing — these
// fields are honored verbatim, not rejected by Ajv at the encode entry (decode never fails; encode is a
// faithful executor that can carry a malformed message). Previously the schema's minimum:8 on byteCount
// and hard enums on messageType/messageId made validate() throw on re-encode.
test('HARTIP never-throws: sub-8 Byte Count and out-of-range type/id round-trip without an Ajv throw', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 5094}},
        // version 1 (matches), messageType 9, messageId 7 (both out of range), byteCount 3 (< 8-byte header)
        {id: 'raw', data: {data: '0109070000000003'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const hip: any = Layer(decoded, 'hartip').data
    assert.strictEqual(hip.messageType, 9, 'out-of-range Message Type decoded verbatim')
    assert.strictEqual(hip.messageId, 7, 'out-of-range Message ID decoded verbatim')
    assert.strictEqual(hip.byteCount, 3, 'sub-8 Byte Count honored verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect, no Ajv throw')
})

// Protocol-specific edge: two HART-IP messages pipelined in one TCP segment. The first message is bounded
// by its Byte Count, so its payload does NOT swallow the trailing message; the trailing bytes fall
// through to raw (a leaf header advances only over its own message). Both directions round-trip byte-for-byte.
test('HARTIP pipelining: the first message is bounded by its Byte Count; the trailing message falls through to raw', async (): Promise<void> => {
    const first: string = '01000000000c000d010000ea60'   // Session Initiate, byteCount 13 => 5-byte payload
    const second: string = '0100020000070008'             // Keep Alive, byteCount 8 (header only, no payload)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 5094, dstport: 40000}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'hartip', 'raw'])
    const hip: any = Layer(decoded, 'hartip').data
    assert.strictEqual(hip.messageId, 0, 'first is Session Initiate')
    assert.strictEqual(hip.payload, '010000ea60', 'payload bounded by its Byte Count — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing Keep Alive left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
