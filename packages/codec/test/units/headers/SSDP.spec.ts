import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// SSDP M-SEARCH request on UDP port 1900 (UPnP Device Architecture). The whole message is kept verbatim,
// so it round-trips byte-for-byte, and the Request-Line is parsed into display-only metadata.
test('SSDP M-SEARCH request: start-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ssdp/msearch').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ssdp'])
    const ssdp: any = Layer(decoded, 'ssdp').data
    assert.strictEqual(ssdp.isRequest, true, 'a Request-Line')
    assert.strictEqual(ssdp.method, 'M-SEARCH')
    assert.strictEqual(ssdp.requestUri, '*', 'SSDP request URI is "*"')
    assert.strictEqual(ssdp.version, 'HTTP/1.1')
    assert.strictEqual(ssdp.statusCode, 0, 'requests have no status code')
    assert.strictEqual(ssdp.reasonPhrase, '')
})

// SSDP NOTIFY advertisement on UDP port 1900. Same verbatim guarantee; the Request-Line method is NOTIFY.
test('SSDP NOTIFY advertisement: start-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ssdp/notify').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ssdp'])
    const ssdp: any = Layer(decoded, 'ssdp').data
    assert.strictEqual(ssdp.isRequest, true, 'a Request-Line')
    assert.strictEqual(ssdp.method, 'NOTIFY')
    assert.strictEqual(ssdp.requestUri, '*')
    assert.strictEqual(ssdp.version, 'HTTP/1.1')
})

// A crafted 200 OK search response: the Status-Line is parsed into statusCode/reasonPhrase, and because
// the message is re-emitted verbatim the whole packet round-trips byte-for-byte.
test('SSDP 200 OK response: status-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    // 'HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nST: upnp:rootdevice\r\nUSN: uuid:...\r\n\r\n'
    const respHex: string = Buffer.from(
        'HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://192.168.1.1:80/desc.xml\r\nST: upnp:rootdevice\r\nUSN: uuid:12345678-1234-1234-1234-123456789012::upnp:rootdevice\r\n\r\n',
        'latin1'
    ).toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '192.168.1.100', protocol: 17}},
        {id: 'udp', data: {srcport: 1900, dstport: 49152}},
        {id: 'ssdp', data: {message: respHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ssdp'])
    const ssdp: any = Layer(decoded, 'ssdp').data
    assert.strictEqual(ssdp.isRequest, false, 'a Status-Line')
    assert.strictEqual(ssdp.method, '', 'responses have no method')
    assert.strictEqual(ssdp.statusCode, 200)
    assert.strictEqual(ssdp.reasonPhrase, 'OK')
    assert.strictEqual(ssdp.version, 'HTTP/1.1')
    assert.strictEqual(ssdp.message, respHex, 'message kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// Non-SSDP traffic on UDP port 1900 must NOT be claimed as SSDP: binary junk, and "NOTIFYX..." (a method
// without the trailing space) are both rejected — they fall through to raw and round-trip.
test('SSDP does not claim non-SSDP traffic on port 1900', async (): Promise<void> => {
    const junk: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '239.255.255.250', protocol: 17}},
        {id: 'udp', data: {srcport: 49152, dstport: 1900}},
        {id: 'raw', data: {data: 'deadbeef00112233'}}
    ])
    const decodedJunk: CodecDecodeResult[] = await AssertRoundTrip(junk.packet)
    AssertLayers(decodedJunk, ['eth', 'ipv4', 'udp', 'raw'])
    assert.ok(!decodedJunk.some((l: CodecDecodeResult): boolean => l.id === 'ssdp'), 'binary junk on 1900 is not SSDP')

    // 'NOTIFYX * HTTP/1.1\r\n\r\n' — a method-looking token WITHOUT the trailing space must be rejected.
    const notifyxHex: string = Buffer.from('NOTIFYX * HTTP/1.1\r\n\r\n', 'latin1').toString('hex')
    const notifyx: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '239.255.255.250', protocol: 17}},
        {id: 'udp', data: {srcport: 49152, dstport: 1900}},
        {id: 'raw', data: {data: notifyxHex}}
    ])
    const decodedNotifyx: CodecDecodeResult[] = await AssertRoundTrip(notifyx.packet)
    assert.ok(!decodedNotifyx.some((l: CodecDecodeResult): boolean => l.id === 'ssdp'), '"NOTIFYX " (no bare method) is not SSDP')
})

// A truncated SSDP message (cut mid-headers) must decode without throwing and re-encode without throwing.
test('SSDP truncated mid-message: decode survives AND re-encodes', async (): Promise<void> => {
    const full: Buffer = LoadPacket('ssdp/notify').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 30))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)
})
