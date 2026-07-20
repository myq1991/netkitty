import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// A real CoAP CON GET request (RFC 7252) on UDP 5683: 4-byte fixed header (version 1, type CON, TKL 4),
// code 0.01 GET, a message id, a 4-byte token, then a Uri-Path option — the whole options+payload
// region is kept verbatim and the datagram round-trips byte-for-byte.
test('CoAP CON GET: fixed header + token decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('coap/get').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'coap'])
    const coap: any = Layer(decoded, 'coap').data
    assert.strictEqual(coap.version, 1, 'CoAP version is always 1')
    assert.strictEqual(coap.type, 0, 'Confirmable (CON)')
    assert.strictEqual(coap.tokenLength, coap.token.length / 2, 'TKL matches the decoded token byte count')
    assert.strictEqual(coap.code, 0x01, '0.01 GET')
})

// Crafting: a codec is a faithful executor — build a CON GET carrying a 4-byte token plus a Uri-Path
// option ("test") and require it to re-emit exactly what was asked for, byte-for-byte.
test('CoAP faithfully encodes a crafted CON GET with a token and round-trips', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 5683}},
        {id: 'coap', data: {
            version: 1, type: 0, tokenLength: 4,
            code: 0x01, messageId: 0x1234,
            token: '74657374',            // "test"
            payload: 'b474657374'          // Uri-Path option (delta 11, len 4) = "test"
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'coap'])
    const coap: any = Layer(decoded, 'coap').data
    assert.strictEqual(coap.type, 0, 'CON re-emitted')
    assert.strictEqual(coap.code, 0x01, 'GET re-emitted')
    assert.strictEqual(coap.messageId, 0x1234, 'message id preserved')
    assert.strictEqual(coap.token, '74657374', 'token preserved verbatim')
    assert.strictEqual(coap.payload, 'b474657374', 'options+payload preserved verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A UDP/5683 datagram whose first byte does not carry Version == 1 is not CoAP and must fall through to
// RawData rather than being mis-claimed.
test('CoAP non-version-1 first byte falls through to RawData', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 5683}},
        {id: 'raw', data: {data: '80011234'}} // version bits = 2, not a CoAP message
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'coap'), 'must not claim a non-version-1 payload as CoAP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw', 'the payload stays raw')
})

test('CoAP truncated mid-header: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('coap/get').buffer
    // Chop into the CoAP header (keep eth+ip+udp, drop most of the CoAP payload).
    await AssertDecodeSurvives(full.subarray(0, 44))
})
