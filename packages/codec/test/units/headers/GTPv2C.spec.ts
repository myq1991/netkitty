import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// GTPv2-C (udp:2123) Echo Request — mandatory 4-octet part (flags/type/length) + seq + spare + a single
// Recovery IE. T flag clear (no TEID). Byte-perfect round-trip + field-tree assertions.
test('GTPv2-C Echo Request: header + IE decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('gtpv2/echo-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'gtpv2'])
    const gtp: any = Layer(decoded, 'gtpv2').data
    assert.strictEqual(gtp.flags.version, 2, 'GTP version 2')
    assert.strictEqual(gtp.flags.piggybacking, false, 'P flag clear')
    assert.strictEqual(gtp.flags.teidFlag, false, 'T flag clear — no TEID')
    assert.strictEqual(gtp.messageType, 1, 'Echo Request')
    assert.strictEqual(gtp.messageLength, 9, 'octet count after the first 4 (seq + spare + Recovery IE)')
    assert.strictEqual(gtp.teid, undefined, 'no TEID field when T is clear')
    assert.strictEqual(gtp.sequenceNumber, 1, '3-byte sequence number')
    assert.deepStrictEqual(gtp.ies, [{type: 3, spare: 0, instance: 0, value: '00'}], 'one Recovery IE (type 3)')
})

// Create Session Request — the T flag is set, so a 4-byte TEID sits between the length field and the
// sequence number. Exercises the TEID-present offset path. Byte-perfect round-trip.
test('GTPv2-C Create Session Request: TEID-present path + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('gtpv2/create-session-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'gtpv2'])
    const gtp: any = Layer(decoded, 'gtpv2').data
    assert.strictEqual(gtp.flags.teidFlag, true, 'T flag set — TEID present')
    assert.strictEqual(gtp.messageType, 32, 'Create Session Request')
    assert.strictEqual(gtp.teid, '11223344', '4-byte TEID between length and sequence number')
    assert.strictEqual(gtp.sequenceNumber, 2, 'sequence number decoded from the post-TEID offset')
    assert.strictEqual(gtp.messageLength, 13, 'TEID(4) + seq(3) + spare(1) + Recovery IE(5)')
    assert.deepStrictEqual(gtp.ies, [{type: 3, spare: 0, instance: 0, value: '07'}])
})

// honor-else-derive Message Length: a crafted Echo Request omits the Message Length — it must be derived
// from the actual seq + spare + IE bytes. The minimal well-formed message re-encodes byte-identically.
test('GTPv2-C derives the Message Length when omitted', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 2123, dstport: 2123}},
        {id: 'gtpv2', data: {flags: {version: 2}, messageType: 1, sequenceNumber: 7, spare: '00', ies: [
            {type: 3, instance: 0, value: '00'}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'gtpv2'])
    const gtp: any = Layer(decoded, 'gtpv2').data
    assert.strictEqual(gtp.messageType, 1, 'Echo Request')
    assert.strictEqual(gtp.messageLength, 9, 'derived: seq(3) + spare(1) + Recovery IE(5)')
    assert.strictEqual(gtp.sequenceNumber, 7)
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted message supplies an explicit (lying) Message Length — it must be honored
// verbatim (not overwritten by the derived value) so a message carrying any length round-trips.
test('GTPv2-C honors an explicitly supplied Message Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 2123, dstport: 2123}},
        {id: 'gtpv2', data: {flags: {version: 2}, messageType: 2, messageLength: 9, sequenceNumber: 5, spare: '00', ies: [
            {type: 3, instance: 0, value: '00'}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const gtp: any = Layer(decoded, 'gtpv2').data
    assert.strictEqual(gtp.messageType, 2, 'Echo Response')
    assert.strictEqual(gtp.messageLength, 9, 'supplied Message Length honored')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a GTPv1-C-style datagram (version 1) on UDP 2123 must NOT be claimed as GTPv2-C (falls
// through to raw); and a truncated GTPv2-C payload must survive decode without throwing.
test('GTPv2-C rejects version != 2 on port 2123, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 2123, dstport: 2123}},
        // First byte 0x30 => version 1 (GTPv1-C), not GTPv2-C.
        {id: 'raw', data: {data: '30010009000001000300010000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'gtpv2'), 'version 1 must not be claimed as GTPv2-C')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    // A GTPv2-C message truncated inside its IE region must decode best-effort without throwing.
    const full: Buffer = LoadPacket('gtpv2/create-session-request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 3))
})
