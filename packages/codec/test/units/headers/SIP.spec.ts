import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Real-shaped SIP REGISTER request on UDP port 5060 (RFC 3261). The whole message is kept verbatim, so
// it round-trips byte-for-byte, and the Request-Line is parsed into display-only metadata.
test('SIP register request: start-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('sip/register').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'sip'])
    const sip: any = Layer(decoded, 'sip').data
    assert.strictEqual(sip.isRequest, true, 'a Request-Line')
    assert.strictEqual(sip.method, 'REGISTER')
    assert.strictEqual(sip.requestUri, 'sip:example.com')
    assert.strictEqual(sip.version, 'SIP/2.0')
    assert.strictEqual(sip.statusCode, 0, 'requests have no status code')
    assert.strictEqual(sip.reasonPhrase, '')
})

// A crafted 200 OK response: the Status-Line is parsed into statusCode/reasonPhrase, and because the
// message is re-emitted verbatim the whole packet round-trips byte-for-byte.
test('SIP 200 OK response: status-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const respHex: string = '5349502f322e3020323030204f4b0d0a5669613a205349502f322e302f554450203132372e302e302e313a353036303b6272616e63683d7a39684734624b3737366173646864730d0a46726f6d3a20416c696365203c7369703a616c696365406578616d706c652e636f6d3e3b7461673d313932383330313737340d0a546f3a20416c696365203c7369703a616c696365406578616d706c652e636f6d3e3b7461673d3337476b4568776c360d0a43616c6c2d49443a206138346234633736653636373130403132372e302e302e310d0a435365713a20312052454749535445520d0a436f6e74656e742d4c656e6774683a20300d0a0d0a'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 5060, dstport: 5060}},
        {id: 'sip', data: {message: respHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'sip'])
    const sip: any = Layer(decoded, 'sip').data
    assert.strictEqual(sip.isRequest, false, 'a Status-Line')
    assert.strictEqual(sip.method, '', 'responses have no method')
    assert.strictEqual(sip.statusCode, 200)
    assert.strictEqual(sip.reasonPhrase, 'OK')
    assert.strictEqual(sip.version, 'SIP/2.0')
    assert.strictEqual(sip.message, respHex, 'message kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// Non-SIP traffic on UDP port 5060 (no request method, no "SIP/2.0" version) must NOT be claimed as SIP
// — it falls through to raw and round-trips.
test('SIP does not claim non-SIP traffic on port 5060', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 5060, dstport: 5060}},
        {id: 'raw', data: {data: 'deadbeef00112233'}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'sip'), 'binary junk on 5060 is not SIP')
})

// A truncated SIP message (cut mid-headers) must decode without throwing and re-encode without throwing.
test('SIP truncated mid-message: decode survives AND re-encodes', async (): Promise<void> => {
    const full: Buffer = LoadPacket('sip/register').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 40))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)
})
