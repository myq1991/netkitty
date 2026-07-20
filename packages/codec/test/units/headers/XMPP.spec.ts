import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// XMPP (RFC 6120, tcp:5222) client-to-server stream open — the whole XML fragment is kept verbatim as
// `message` and re-emitted byte-for-byte; the head is parsed into display-only metadata.
test('XMPP stream open: layers + metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('xmpp/stream-open').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'xmpp'])
    const xmpp: any = Layer(decoded, 'xmpp').data
    assert.strictEqual(xmpp.rootElement, 'stream:stream', 'first element is the stream root')
    assert.strictEqual(xmpp.isStreamHeader, true, 'recognized as a stream header')
    assert.strictEqual(xmpp.hasXmlDeclaration, true, 'leading <?xml ...?> declaration present')
    const message: string = Buffer.from(xmpp.message, 'hex').toString('latin1')
    assert.ok(message.startsWith("<?xml version='1.0'?><stream:stream"), 'verbatim XML preserved')
})

// Crafting: a bare <message> stanza (no XML declaration) on 5269 (server-to-server). The verbatim
// message must re-encode byte-identically and the metadata must reflect a stanza, not a stream header.
test('XMPP faithfully encodes a crafted <message> stanza and round-trips byte-for-byte', async (): Promise<void> => {
    const stanza: string = "<message to='a@b' from='c@d'><body>hi</body></message>"
    const messageHex: string = Buffer.from(stanza, 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 5269}},
        {id: 'xmpp', data: {message: messageHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'xmpp'])
    const xmpp: any = Layer(decoded, 'xmpp').data
    assert.strictEqual(xmpp.rootElement, 'message', 'first element is a message stanza')
    assert.strictEqual(xmpp.isStreamHeader, false, 'a stanza is not a stream header')
    assert.strictEqual(xmpp.hasXmlDeclaration, false, 'no XML declaration on a mid-stream stanza')
    assert.strictEqual(xmpp.message, messageHex, 'verbatim message preserved')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/5222 payload whose first non-whitespace byte is not '<' (e.g. a TLS record after
// STARTTLS, leading 0x16) must NOT be claimed as XMPP; and a truncated fragment must survive decode.
test('XMPP rejects non-XML payload on port 5222, and truncation survives', async (): Promise<void> => {
    // A non-XML, non-protocol payload on the XMPP port must fall through to raw. (Note: a TLS record such
    // as 16 03 03 … would legitimately be claimed by the TLS content heuristic — e.g. XMPP STARTTLS — so
    // use bytes that match no protocol signature to exercise the pure fall-through-to-raw path.)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 5222}},
        {id: 'raw', data: {data: 'deadbeefcafef00dba5e'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'xmpp'), 'non-XML payload must not be claimed as XMPP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('xmpp/stream-open').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 20))
})
