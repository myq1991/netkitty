import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// A WHOIS client request (RFC 3912) on TCP port 43: the whole payload is the single US-ASCII line
// "example.com\r\n". It is kept verbatim (byte-perfect), and the first line is parsed into display-only
// metadata {query, isQuery}.
test('WHOIS request: query metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('whois/query').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'whois'])
    const whois: any = Layer(decoded, 'whois').data
    assert.strictEqual(whois.isQuery, true, 'the payload is a single CR-LF-terminated request line')
    assert.strictEqual(whois.query, 'example.com', 'the query domain is parsed from the first line')
    assert.strictEqual(whois.message, Buffer.from('example.com\r\n', 'latin1').toString('hex'), 'message holds the whole payload verbatim')
})

// The verbatim guarantee: a crafted request line is re-emitted byte-identical from the `message` field,
// never reconstructed from the parsed metadata.
test('WHOIS crafted request re-encodes byte-identical (verbatim)', async (): Promise<void> => {
    const payload: string = Buffer.from('www.iana.org\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 52012, dstport: 43}},
        {id: 'whois', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'whois'])
    const whois: any = Layer(decoded, 'whois').data
    assert.strictEqual(whois.isQuery, true, 'single CR-LF-terminated line → a request')
    assert.strictEqual(whois.query, 'www.iana.org', 'query parsed from the crafted line')
    assert.strictEqual(whois.message, payload, 'the request line is kept verbatim')
})

// Boundary edge: a request line with NO trailing CR LF (e.g. a client that omitted the terminator, or a
// truncated first fragment). The whole payload is still kept verbatim and round-trips byte-for-byte;
// query is the whole line, and isQuery is false because there is no single-line terminator.
test('WHOIS request without CRLF: verbatim, isQuery false', async (): Promise<void> => {
    const payload: string = Buffer.from('example.com', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 52012, dstport: 43}},
        {id: 'whois', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'whois'])
    const whois: any = Layer(decoded, 'whois').data
    assert.strictEqual(whois.isQuery, false, 'no CR-LF terminator → not the classic single-line request shape')
    assert.strictEqual(whois.query, 'example.com', 'the whole (unterminated) line is the query')
    assert.strictEqual(whois.message, payload, 'kept verbatim even without a terminator')
})

// Port confinement (no heuristicFallback): a WHOIS-looking request line on a non-43 port must NOT be
// claimed as WHOIS — it falls through to raw. And a truncated payload on port 43 must decode without
// throwing and remain re-encodable.
test('WHOIS is confined to port 43; truncation survives', async (): Promise<void> => {
    const requestHex: string = Buffer.from('example.com\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 52012, dstport: 9999}}, // not port 43
        {id: 'raw', data: {data: requestHex}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'whois'), 'a WHOIS request line off port 43 must not be claimed by WHOIS')

    // A request cut mid-line on port 43 must decode without throwing and remain re-encodable.
    const full: Buffer = LoadPacket('whois/query').buffer
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 4))
    await codec.encode(survived)
})

// A server response (RFC 3912): free-form multi-line US-ASCII text (the registry record). It has no
// single-line terminator, so isQuery is false and query holds the first line; the whole record is kept
// verbatim and round-trips byte-for-byte.
test('WHOIS multi-line response round-trips byte-perfect', async (): Promise<void> => {
    const response: string = 'Domain Name: EXAMPLE.COM\r\nRegistrar: RESERVED\r\n% comment\r\n'
    const payload: string = Buffer.from(response, 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 43, dstport: 52012}},
        {id: 'whois', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'whois'])
    const whois: any = Layer(decoded, 'whois').data
    assert.strictEqual(whois.isQuery, false, 'a multi-line response is not the single-line request shape')
    assert.strictEqual(whois.query, 'Domain Name: EXAMPLE.COM', 'query holds the response first line')
    assert.strictEqual(whois.message, payload, 'the whole record is kept verbatim')
})
