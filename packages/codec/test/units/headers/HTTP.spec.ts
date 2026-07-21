import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Real captured HTTP GET request on TCP port 8000 (RFC 7230). The whole message is kept verbatim, so it
// round-trips byte-for-byte, and the Request-Line is parsed into display-only metadata.
test('HTTP GET request: start-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('http/get').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'http'])
    const http: any = Layer(decoded, 'http').data
    assert.strictEqual(http.isRequest, true, 'a Request-Line')
    assert.strictEqual(http.method, 'GET')
    assert.ok(http.version.startsWith('HTTP/1.'), `version '${http.version}' is HTTP/1.x`)
    assert.strictEqual(http.statusCode, 0, 'requests have no status code')
    // The message field re-encodes byte-perfect (verbatim guarantee).
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), LoadPacket('http/get').hex)
})

// A crafted 200 OK response: the Status-Line is parsed into statusCode/reasonPhrase, and because the
// message is re-emitted verbatim the whole packet round-trips byte-for-byte.
test('HTTP 200 OK response: status-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    // 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
    const respHex: string = Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 80, dstport: 54321}},
        {id: 'http', data: {message: respHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'http'])
    const http: any = Layer(decoded, 'http').data
    assert.strictEqual(http.isRequest, false, 'a Status-Line')
    assert.strictEqual(http.method, '', 'responses have no method')
    assert.strictEqual(http.statusCode, 200)
    assert.strictEqual(http.reasonPhrase, 'OK')
    assert.strictEqual(http.version, 'HTTP/1.1')
    assert.strictEqual(http.message, respHex, 'message kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// Non-HTTP traffic on TCP port 80 must NOT be claimed as HTTP: binary junk, and "GETX..." (a method
// without the trailing space) are both rejected — they fall through to raw and round-trip.
test('HTTP does not claim non-HTTP traffic on port 80', async (): Promise<void> => {
    const junk: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 80}},
        {id: 'raw', data: {data: 'deadbeef00112233'}}
    ])
    const decodedJunk: CodecDecodeResult[] = await AssertRoundTrip(junk.packet)
    AssertLayers(decodedJunk, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decodedJunk.some((l: CodecDecodeResult): boolean => l.id === 'http'), 'binary junk on 80 is not HTTP')

    // 'GETX / HTTP/1.1\r\n\r\n' — a method-looking token WITHOUT the trailing space must be rejected.
    const getxHex: string = Buffer.from('GETX / HTTP/1.1\r\n\r\n', 'latin1').toString('hex')
    const getx: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 80}},
        {id: 'raw', data: {data: getxHex}}
    ])
    const decodedGetx: CodecDecodeResult[] = await AssertRoundTrip(getx.packet)
    assert.ok(!decodedGetx.some((l: CodecDecodeResult): boolean => l.id === 'http'), '"GETX " (no bare method) is not HTTP')
})

// A truncated HTTP message (cut mid-headers) must decode without throwing and re-encode without
// throwing; a body-carrying message round-trips byte-perfect (verbatim guarantee).
test('HTTP truncated mid-message survives; body-carrying message round-trips', async (): Promise<void> => {
    const full: Buffer = LoadPacket('http/get').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 20))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)

    // A POST with a body: headers + blank line + arbitrary body bytes are all kept verbatim.
    const bodyHex: string = Buffer.from('POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 33333, dstport: 80}},
        {id: 'http', data: {message: bodyHex}}
    ])
    const roundTripped: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const http: any = Layer(roundTripped, 'http').data
    assert.strictEqual(http.method, 'POST')
    assert.strictEqual(http.requestUri, '/submit')
    assert.strictEqual(http.message, bodyHex, 'body kept verbatim')
})
