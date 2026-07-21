import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Real captured IMAP command on TCP port 143 (RFC 3501). The whole message is kept verbatim, so it
// round-trips byte-for-byte, and the first line is parsed into display-only metadata.
test('IMAP command: first-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('imap/command').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'imap'])
    const imap: any = Layer(decoded, 'imap').data
    assert.strictEqual(imap.kind, 'command', 'a client command')
    assert.strictEqual(imap.tag, 'a001')
    assert.strictEqual(imap.command, 'LOGIN')
    assert.strictEqual(imap.text, 'alice secret')
    assert.strictEqual(imap.status, '', 'commands have no status condition')
    // The message field re-encodes byte-perfect (verbatim guarantee).
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), LoadPacket('imap/command').hex)
})

// Crafted IMAP server responses: a tagged completion carries a tag + OK/NO/BAD status; an untagged
// response is `* ...`. Because the message is re-emitted verbatim the whole packet round-trips byte-for-byte.
test('IMAP response: tagged status + untagged metadata + byte-perfect round-trip', async (): Promise<void> => {
    // 'a001 OK LOGIN completed\r\n' — a tagged completion response.
    const okHex: string = Buffer.from('a001 OK LOGIN completed\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 143, dstport: 54321}},
        {id: 'imap', data: {message: okHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'imap'])
    const imap: any = Layer(decoded, 'imap').data
    assert.strictEqual(imap.kind, 'tagged', 'a tagged server response')
    assert.strictEqual(imap.tag, 'a001')
    assert.strictEqual(imap.status, 'OK')
    assert.strictEqual(imap.command, '', 'tagged responses carry a status, not a command')
    assert.strictEqual(imap.text, 'LOGIN completed')
    assert.strictEqual(imap.message, okHex, 'message kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))

    // '* 18 EXISTS\r\n' — an untagged server response.
    const untaggedHex: string = Buffer.from('* 18 EXISTS\r\n', 'latin1').toString('hex')
    const un: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 143, dstport: 54321}},
        {id: 'imap', data: {message: untaggedHex}}
    ])
    const decodedUn: CodecDecodeResult[] = await AssertRoundTrip(un.packet)
    const imapUn: any = Layer(decodedUn, 'imap').data
    assert.strictEqual(imapUn.kind, 'untagged')
    assert.strictEqual(imapUn.tag, '', 'untagged responses have no tag')
    assert.strictEqual(imapUn.status, '', '`18` is not an OK/NO/BAD status')
    assert.strictEqual(imapUn.text, '18 EXISTS')
})

// Non-IMAP traffic on TCP port 143 must NOT be claimed as IMAP: binary junk, and "HELLO x\r\n" (a
// `<tag> VERB` shape whose second token is not a known IMAP verb nor an OK/NO/BAD status) are both
// rejected — they fall to raw.
test('IMAP does not claim non-IMAP traffic on port 143', async (): Promise<void> => {
    const junk: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 143}},
        {id: 'raw', data: {data: 'deadbeef00112233'}}
    ])
    const decodedJunk: CodecDecodeResult[] = await AssertRoundTrip(junk.packet)
    AssertLayers(decodedJunk, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decodedJunk.some((l: CodecDecodeResult): boolean => l.id === 'imap'), 'binary junk on 143 is not IMAP')

    // 'HELLO x\r\n' — second token is not a known IMAP verb/status, so it must be rejected.
    const helloHex: string = Buffer.from('HELLO x\r\n', 'latin1').toString('hex')
    const hello: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 143}},
        {id: 'raw', data: {data: helloHex}}
    ])
    const decodedHello: CodecDecodeResult[] = await AssertRoundTrip(hello.packet)
    assert.ok(!decodedHello.some((l: CodecDecodeResult): boolean => l.id === 'imap'), '"HELLO x" is not an IMAP line')
})

// Port-confinement regression: IMAP must NOT be recognized off its port buckets (no heuristicFallback).
// IMAP shares a generic `<tag> VERB` line shape with other text protocols, so an IMAP-looking
// 'a001 LOGIN x y' line on a non-143/993 port (here 9999) must decode as raw, not imap — this locks in
// the no-heuristicFallback design.
test('IMAP does not steal a LOGIN line off its port buckets (no heuristicFallback)', async (): Promise<void> => {
    const loginHex: string = Buffer.from('a001 LOGIN x y\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 9999}}, // NOT an IMAP port
        {id: 'raw', data: {data: loginHex}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'imap'), 'a LOGIN line on port 9999 must not be claimed off the tcp:143/tcp:993 buckets')
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
})

// A truncated IMAP message (cut mid-line) must decode without throwing and re-encode without throwing; a
// command carrying arguments (FETCH 1 BODY[]) round-trips byte-perfect (verbatim guarantee).
test('IMAP truncated survives; command with arguments round-trips', async (): Promise<void> => {
    const full: Buffer = LoadPacket('imap/command').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 4))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)

    // A tagged FETCH command with arguments is kept verbatim.
    const fetchHex: string = Buffer.from('A2 FETCH 1 BODY[]\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 33333, dstport: 143}},
        {id: 'imap', data: {message: fetchHex}}
    ])
    const roundTripped: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const imap: any = Layer(roundTripped, 'imap').data
    assert.strictEqual(imap.kind, 'command')
    assert.strictEqual(imap.tag, 'A2')
    assert.strictEqual(imap.command, 'FETCH')
    assert.strictEqual(imap.text, '1 BODY[]')
    assert.strictEqual(imap.message, fetchHex, 'arguments kept verbatim')
})
