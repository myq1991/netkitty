import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Real-shape Finger verbose query (RFC 1288) on TCP port 79: the client sends "/W root\r\n" — the verbose
// switch {W}="/W", the username "root", terminated by CR LF. The whole payload is kept verbatim
// (byte-perfect); the first line is parsed into display-only metadata {isVerbose, query}.
test('Finger query: verbose switch + username, byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('finger/query').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'finger'])
    const finger: any = Layer(decoded, 'finger').data
    assert.strictEqual(finger.isVerbose, true, 'the query opens with the /W verbose switch')
    assert.strictEqual(finger.query, 'root', 'the parsed username is root (switch + whitespace stripped)')
    assert.strictEqual(finger.message, '2f5720726f6f740d0a', 'message holds the whole payload verbatim')
})

// A plain username query (no /W switch) on port 79 is still Finger — the byte stream is kept verbatim and
// round-trips byte-for-byte, and the display metadata report the username with isVerbose false.
test('Finger plain username query re-encodes byte-identical (verbatim)', async (): Promise<void> => {
    const payload: string = Buffer.from('jdoe\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49812, dstport: 79}},
        {id: 'finger', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'finger'])
    const finger: any = Layer(decoded, 'finger').data
    assert.strictEqual(finger.isVerbose, false, 'no /W → not verbose')
    assert.strictEqual(finger.query, 'jdoe', 'the username is parsed for display')
    assert.strictEqual(finger.message, payload, 'the byte stream is kept verbatim')
})

// Boundary: the empty "list all users" query is a bare CR LF ({C} with no {U}). It has no username, so the
// display parse yields an empty query (summarized as "list all") and still round-trips byte-for-byte.
test('Finger empty list-all query: bare CRLF round-trips', async (): Promise<void> => {
    const payload: string = Buffer.from('\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49812, dstport: 79}},
        {id: 'finger', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'finger'])
    const finger: any = Layer(decoded, 'finger').data
    assert.strictEqual(finger.isVerbose, false, 'the empty query is not verbose')
    assert.strictEqual(finger.query, '', 'no username → empty query')
    assert.strictEqual(finger.message, '0d0a', 'the bare CRLF is kept verbatim')
})

// Port confinement (no heuristicFallback): a Finger-looking text payload on a non-79 port must NOT be
// claimed as Finger — it falls through to raw. And a truncated payload on port 79 must decode without
// throwing and remain re-encodable.
test('Finger is confined to port 79; truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49812, dstport: 9999}}, // not port 79
        {id: 'raw', data: {data: Buffer.from('/W root\r\n', 'latin1').toString('hex')}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'finger'), 'Finger text off port 79 must not be claimed')

    // A query cut mid-line on port 79 (no CR LF) must decode without throwing and stay re-encodable.
    const full: Buffer = LoadPacket('finger/query').buffer
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 4))
    await codec.encode(survived)
})

// Protocol edge: the verbose switch with no username ("/W\r\n") sets isVerbose true with an empty query,
// and a payload with NO line terminator still parses (the whole line is the query) — both verbatim.
test('Finger verbose switch alone and missing CRLF parse without throwing', async (): Promise<void> => {
    const bare: string = Buffer.from('/W\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49812, dstport: 79}},
        {id: 'finger', data: {message: bare}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const finger: any = Layer(decoded, 'finger').data
    assert.strictEqual(finger.isVerbose, true, '/W alone is still the verbose switch')
    assert.strictEqual(finger.query, '', 'no username after /W → empty query')
    assert.strictEqual(finger.message, bare, 'the switch-only query is kept verbatim')

    // No CR LF at all: a username with no line ending is still carried verbatim and parsed as the query.
    const noEol: string = Buffer.from('root', 'latin1').toString('hex')
    const {packet: packet2}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49812, dstport: 79}},
        {id: 'finger', data: {message: noEol}}
    ])
    const decoded2: CodecDecodeResult[] = await AssertRoundTrip(packet2)
    const finger2: any = Layer(decoded2, 'finger').data
    assert.strictEqual(finger2.query, 'root', 'a line with no CR LF is parsed as the whole query')
    assert.strictEqual(finger2.message, noEol, 'kept verbatim with no terminator')
})
