import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Real RTSP DESCRIBE request on TCP port 554 (RFC 2326). The whole message is kept verbatim, so it
// round-trips byte-for-byte, and the Request-Line + CSeq are parsed into display-only metadata.
test('RTSP DESCRIBE request: start-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rtsp/describe').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'rtsp'])
    const rtsp: any = Layer(decoded, 'rtsp').data
    assert.strictEqual(rtsp.isRequest, true, 'a Request-Line')
    assert.strictEqual(rtsp.method, 'DESCRIBE')
    assert.strictEqual(rtsp.requestUri, 'rtsp://example.com/stream')
    assert.strictEqual(rtsp.version, 'RTSP/1.0')
    assert.strictEqual(rtsp.statusCode, 0, 'requests have no status code')
    assert.strictEqual(rtsp.cseq, 2, 'CSeq header parsed')
    // The message field re-encodes byte-perfect (verbatim guarantee).
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), LoadPacket('rtsp/describe').hex)
})

// A crafted 200 OK response: the Status-Line is parsed into statusCode/reasonPhrase and the CSeq into
// cseq, and because the message is re-emitted verbatim the whole packet round-trips byte-for-byte.
test('RTSP 200 OK response: status-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    // 'RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n'
    const respHex: string = Buffer.from('RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 554, dstport: 54321}},
        {id: 'rtsp', data: {message: respHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'rtsp'])
    const rtsp: any = Layer(decoded, 'rtsp').data
    assert.strictEqual(rtsp.isRequest, false, 'a Status-Line')
    assert.strictEqual(rtsp.method, '', 'responses have no method')
    assert.strictEqual(rtsp.statusCode, 200)
    assert.strictEqual(rtsp.reasonPhrase, 'OK')
    assert.strictEqual(rtsp.version, 'RTSP/1.0')
    assert.strictEqual(rtsp.cseq, 2, 'CSeq header parsed')
    assert.strictEqual(rtsp.message, respHex, 'message kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// Non-RTSP traffic on TCP port 554 must NOT be claimed as RTSP: binary junk, and "PLAYX..." (a method
// without the trailing space) are both rejected; and an HTTP request line ("GET / HTTP/1.1") must NOT
// be claimed as RTSP — the RTSP and HTTP start-line signatures are disjoint.
test('RTSP does not claim non-RTSP traffic (binary junk, PLAYX, HTTP GET)', async (): Promise<void> => {
    const junk: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 554}},
        {id: 'raw', data: {data: 'deadbeef00112233'}}
    ])
    const decodedJunk: CodecDecodeResult[] = await AssertRoundTrip(junk.packet)
    AssertLayers(decodedJunk, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decodedJunk.some((l: CodecDecodeResult): boolean => l.id === 'rtsp'), 'binary junk on 554 is not RTSP')

    // 'PLAYX rtsp://x RTSP/1.0\r\n\r\n' — a method-looking token WITHOUT the trailing space is rejected.
    const playxHex: string = Buffer.from('PLAYX rtsp://x RTSP/1.0\r\n\r\n', 'latin1').toString('hex')
    const playx: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 554}},
        {id: 'raw', data: {data: playxHex}}
    ])
    const decodedPlayx: CodecDecodeResult[] = await AssertRoundTrip(playx.packet)
    assert.ok(!decodedPlayx.some((l: CodecDecodeResult): boolean => l.id === 'rtsp'), '"PLAYX " (no bare method) is not RTSP')

    // 'GET / HTTP/1.1\r\n\r\n' on port 554 — an HTTP request line must NOT be claimed as RTSP (disjoint
    // signatures: GET is not an RTSP method and "HTTP/1." is not "RTSP/").
    const getHex: string = Buffer.from('GET / HTTP/1.1\r\n\r\n', 'latin1').toString('hex')
    const get: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 554}},
        {id: 'raw', data: {data: getHex}}
    ])
    const decodedGet: CodecDecodeResult[] = await AssertRoundTrip(get.packet)
    assert.ok(!decodedGet.some((l: CodecDecodeResult): boolean => l.id === 'rtsp'), 'an HTTP GET line is not RTSP')
})

// A truncated RTSP message (cut mid-headers) must decode without throwing and re-encode without
// throwing; a request carrying an SDP body round-trips byte-perfect (verbatim guarantee).
test('RTSP truncated mid-message survives; SDP-body message round-trips', async (): Promise<void> => {
    const full: Buffer = LoadPacket('rtsp/describe').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 20))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)

    // An ANNOUNCE carrying an SDP body: headers + blank line + arbitrary body bytes are kept verbatim.
    const announce: string = 'ANNOUNCE rtsp://example.com/stream RTSP/1.0\r\nCSeq: 3\r\nContent-Type: application/sdp\r\nContent-Length: 46\r\n\r\nv=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=stream\r\nt=0 0\r\n'
    const bodyHex: string = Buffer.from(announce, 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 33333, dstport: 554}},
        {id: 'rtsp', data: {message: bodyHex}}
    ])
    const roundTripped: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const rtsp: any = Layer(roundTripped, 'rtsp').data
    assert.strictEqual(rtsp.method, 'ANNOUNCE')
    assert.strictEqual(rtsp.requestUri, 'rtsp://example.com/stream')
    assert.strictEqual(rtsp.cseq, 3, 'CSeq header parsed')
    assert.strictEqual(rtsp.message, bodyHex, 'body kept verbatim')
})
