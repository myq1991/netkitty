import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, LayerIds, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// R-GOOSE (IEC 61850-90-5 Session) over eth/IPv4/UDP:102. The session byte layout was cross-checked
// against tshark 4.6.7's own R-GOOSE dissector (packet-goose.c dissect_rgoose). Slice 1: the session
// header owns the whole payload + signature; each payload item's APDU is bounded raw hex (no recursion
// into the GOOSE/SV decoders), so the trailing HMAC signature is preserved rather than swallowed.
test('R-GOOSE fixture: session decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rgoose/goose').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'r-session'])
    const s: any = Layer(decoded, 'r-session').data
    assert.strictEqual(s.si, 0xA1, 'Session Identifier = non-tunnelled GOOSE')
    assert.strictEqual(s.spduNumber, 64, 'SPDU number')
    assert.strictEqual(s.version, 1, 'session version')
    assert.strictEqual(s.security.keyId, 1, 'Key ID')
    assert.strictEqual(s.security.initVecLength, 0, 'no init vector')
    assert.ok(Array.isArray(s.payloadItems) && s.payloadItems.length === 1, 'one payload item')
    assert.strictEqual(s.payloadItems[0].payloadType, 0x81, 'payload type = GOOSE')
    assert.strictEqual(s.payloadItems[0].appid, 1, 'payload item APPID')
    assert.strictEqual(s.payloadItems[0].apduLength, 137, 'APDU length')
    assert.ok(s.payloadItems[0].apdu.startsWith('6181'), 'APDU begins with the goosePdu BER tag')
    assert.strictEqual(s.signature, '8510abababababababababababababababab', 'HMAC signature trailer preserved')
})

// R-SV branch: same session framing, SI=0xA2 and payload type 0x82 (savPdu). Crafted, then required to
// re-encode byte-identically — proves the single header serves both R-GOOSE and R-SV off the SI byte.
test('R-SV crafted (SI 0xA2 / payload type 0x82): decode → byte-identical re-encode', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:0c:cd:04:00:01', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 102}},
        {id: 'r-session', data: {
            si: 0xA2, spduNumber: 7, version: 1,
            security: {timeCurrentKey: 0, timeNextKey: 0xffff, keyId: 2, initVecLength: 0, initVec: ''},
            payloadItems: [{payloadType: 0x82, simulation: 0, appid: 0x4000, apdu: '60088001018200030102ab'}],
            signature: '850400112233'
        }}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'r-session'])
    const s: any = Layer(decoded, 'r-session').data
    assert.strictEqual(s.si, 0xA2, 'R-SV session identifier')
    assert.strictEqual(s.payloadItems[0].payloadType, 0x82, 'payload type = SV')
    assert.strictEqual(s.payloadItems[0].appid, 0x4000)
    assert.strictEqual(s.signature, '850400112233', 'signature preserved on the R-SV branch')
})

// Two payload items in one SPDU: the array walk must recover both (accumulating 6 + APDU length until
// the payload length is consumed) and re-encode byte-perfect.
test('R-GOOSE multi payload item: both items decoded + byte-perfect', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:0c:cd:01:00:01', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 102}},
        {id: 'r-session', data: {
            si: 0xA1, spduNumber: 9, version: 1,
            security: {timeCurrentKey: 1, timeNextKey: 0xffff, keyId: 3, initVecLength: 0, initVec: ''},
            payloadItems: [
                {payloadType: 0x81, simulation: 0, appid: 0x0001, apdu: '610480020001'.slice(0)},
                {payloadType: 0x81, simulation: 1, appid: 0x0002, apdu: '6106800101810102'}
            ],
            signature: ''
        }}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const s: any = Layer(decoded, 'r-session').data
    assert.strictEqual(s.payloadItems.length, 2, 'both payload items recovered by the array walk')
    assert.strictEqual(s.payloadItems[0].appid, 0x0001)
    assert.strictEqual(s.payloadItems[1].appid, 0x0002)
    assert.strictEqual(s.payloadItems[1].simulation, 1, 'per-item simulation flag')
})

// The trailing signature/HMAC must survive decode→encode untouched (it is bounded by the payload length,
// not folded into the last APDU).
test('R-GOOSE signature preservation: HMAC trailer round-trips byte-perfect', async (): Promise<void> => {
    const original: Buffer = LoadPacket('rgoose/goose').buffer
    const decoded: CodecDecodeResult[] = await codec.decode(original)
    const s: any = Layer(decoded, 'r-session').data
    assert.strictEqual(s.signature, '8510abababababababababababababababab')
    // Mutate only the signature and confirm it reappears exactly (not absorbed by the APDU).
    s.signature = '85043c3c3c3c'
    const encoded: CodecEncodeResult = await codec.encode(decoded)
    const redecoded: CodecDecodeResult[] = await codec.decode(encoded.packet)
    assert.strictEqual((Layer(redecoded, 'r-session').data as any).signature, '85043c3c3c3c', 'edited signature survives a re-encode')
    assert.strictEqual((Layer(redecoded, 'r-session').data as any).payloadItems[0].apduLength, 137, 'APDU length unchanged by the signature edit')
})

// Regression (critic finding): the signature boundary is taken from the ACTUAL decoded item bytes on both
// decode and encode, so even a crafted payloadLength that overshoots the real item span by a partial item
// (fewer than the 6 bytes needed for another item header) with a trailing signature round-trips exactly —
// the leftover gap bytes fold into the verbatim signature rather than being dropped.
test('R-GOOSE crafted payloadLength overshoot + signature still round-trips (symmetric boundary)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:01', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '224.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 102}},
        {id: 'r-session', data: {
            si: 0xA1, spduNumber: 5, version: 1,
            security: {timeCurrentKey: 0, timeNextKey: 0xffff, keyId: 1, initVecLength: 0, initVec: ''},
            // Item span is 6 + 3 = 9 bytes, but payloadLength is honored as 12 (overshoots by 3 — fewer
            // than a 6-byte item header). A signature follows.
            payloadLength: 12,
            payloadItems: [{payloadType: 0x81, simulation: 0, appid: 0x0001, apduLength: 3, apdu: 'aabbcc'}],
            signature: '85049988776655'
        }}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const s: any = Layer(decoded, 'r-session').data
    assert.strictEqual(s.payloadItems[0].apdu, 'aabbcc', 'the real item APDU is intact')
    // The 3 overshoot gap bytes fold into the verbatim signature ahead of the real HMAC — no byte dropped.
    assert.ok(s.signature.endsWith('85049988776655'), 'the trailing signature survives intact')
})

// Negatives: a truncated SPDU must still decode (error-accumulation contract) and round-trip; a UDP:102
// payload whose first byte is not a valid Session Identifier must NOT be claimed as R-GOOSE.
test('R-GOOSE negative: truncation survives; non-90-5 UDP:102 payload falls through to raw', async (): Promise<void> => {
    const truncated: Buffer = LoadPacket('rgoose/goose').buffer.subarray(0, 100)
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(truncated)
    assert.ok(survived.some((l: CodecDecodeResult): boolean => l.id === 'r-session'), 'truncated frame still decodes an r-session layer')
    //A deliberately truncated frame cannot round-trip byte-perfect (UDP length/checksum are recomputed),
    //but re-encoding must not throw (error-accumulation contract).
    const reencoded: CodecEncodeResult = await codec.encode(survived)
    assert.ok(reencoded.packet.length > 0, 'truncated frame re-encodes without throwing')

    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:0c:cd:01:00:01', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 102}},
        {id: 'raw', data: {data: 'ff'.repeat(40)}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!LayerIds(decoded).includes('r-session'), 'a non-SI first byte on UDP:102 is not R-GOOSE')
})
