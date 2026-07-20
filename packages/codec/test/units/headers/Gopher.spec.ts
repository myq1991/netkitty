import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Real-shape Gopher request (RFC 1436) on TCP port 70: the client sends the selector line
// "/rfc/rfc1436.txt\r\n" naming the requested item. The whole payload is kept verbatim (byte-perfect);
// the first line is parsed into display-only metadata {isRequest, selector}.
test('Gopher request: selector line, byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('gopher/request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'gopher'])
    const gopher: any = Layer(decoded, 'gopher').data
    assert.strictEqual(gopher.isRequest, true, 'dst port 70 marks a client request')
    assert.strictEqual(gopher.selector, '/rfc/rfc1436.txt', 'the requested selector string')
    assert.strictEqual(gopher.searchTerm, '', 'a plain request has no TAB search term')
    assert.strictEqual(gopher.hasTerminator, false, 'a request line is not "." terminated')
    assert.strictEqual(gopher.message, '2f7266632f726663313433362e7478740d0a', 'message holds the whole payload verbatim')
})

// Crafted Gopher menu response on TCP port 70 (src port 70 -> response direction): two directory item
// lines followed by the lone "." end-of-transmission line. A verbatim message is the source of truth and
// round-trips byte-for-byte; the metadata report the response direction, the item count and the terminator.
test('Gopher faithfully encodes a crafted menu response (verbatim)', async (): Promise<void> => {
    const menu: string = '0About this server\t/about.txt\tgopher.example\t70\r\n' +
        '1Documents\t/docs\tgopher.example\t70\r\n.\r\n'
    const payload: string = Buffer.from(menu, 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 70, dstport: 40000}},
        {id: 'gopher', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'gopher'])
    const gopher: any = Layer(decoded, 'gopher').data
    assert.strictEqual(gopher.isRequest, false, 'src port 70 marks a server response')
    assert.strictEqual(gopher.itemCount, 2, 'two menu item lines before the "." terminator')
    assert.strictEqual(gopher.hasTerminator, true, 'the listing ends with the "." line')
    assert.strictEqual(gopher.message, payload, 'the byte stream is kept verbatim')
})

// Type-7 index-search request: "/search\tgopher protocol\r\n" — the selector, a TAB, then the search
// term. Kept verbatim and round-trips byte-for-byte; the selector and searchTerm are split on the TAB.
test('Gopher parses a type-7 search request (selector + TAB + search)', async (): Promise<void> => {
    const search: string = '/search\tgopher protocol\r\n'
    const payload: string = Buffer.from(search, 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.2', dip: '192.0.2.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 50000, dstport: 70}},
        {id: 'gopher', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const gopher: any = Layer(decoded, 'gopher').data
    assert.strictEqual(gopher.isRequest, true, 'dst port 70 marks a request')
    assert.strictEqual(gopher.selector, '/search', 'selector before the TAB')
    assert.strictEqual(gopher.searchTerm, 'gopher protocol', 'search term after the TAB')
    assert.strictEqual(gopher.message, payload, 'kept verbatim')
})

// Port confinement (no heuristicFallback): a Gopher-looking selector line on a non-70 port must NOT be
// claimed as Gopher — it falls through to raw. And a truncated payload on port 70 must decode without
// throwing and remain re-encodable.
test('Gopher is confined to port 70; truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 49798, dstport: 9999}}, // not port 70
        {id: 'raw', data: {data: Buffer.from('/rfc/rfc1436.txt\r\n', 'latin1').toString('hex')}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'gopher'), 'Gopher text off port 70 must not be claimed')

    // A request cut mid-line on port 70 must decode without throwing and stay re-encodable.
    const full: Buffer = LoadPacket('gopher/request').buffer
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 6))
    await codec.encode(survived)
})

// Protocol edge: a non-text / malformed binary payload on port 70 is still claimed and kept verbatim
// without throwing (no printable-text gate), and a payload with no line terminator still parses (the
// whole payload is the selector). Both round-trip byte-for-byte.
test('Gopher keeps a binary payload verbatim and parses a terminator-less selector', async (): Promise<void> => {
    const binary: string = '00ff8801deadbeef'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49798, dstport: 70}},
        {id: 'gopher', data: {message: binary}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const gopher: any = Layer(decoded, 'gopher').data
    assert.strictEqual(gopher.message, binary, 'binary payload kept verbatim without throwing')

    // A selector with no CR LF is still parsed as the whole line.
    const noEol: string = Buffer.from('/no-terminator', 'latin1').toString('hex')
    const {packet: packet2}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49798, dstport: 70}},
        {id: 'gopher', data: {message: noEol}}
    ])
    const decoded2: CodecDecodeResult[] = await AssertRoundTrip(packet2)
    const gopher2: any = Layer(decoded2, 'gopher').data
    assert.strictEqual(gopher2.selector, '/no-terminator', 'a selector with no CR LF is still parsed')
    assert.strictEqual(gopher2.message, noEol, 'kept verbatim with no terminator')
})
