import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Real captured NNTP command on TCP port 119 (RFC 3977). The whole message is kept verbatim, so it
// round-trips byte-for-byte, and the first line is parsed into display-only metadata.
test('NNTP command: first-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('nntp/command').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'nntp'])
    const nntp: any = Layer(decoded, 'nntp').data
    assert.strictEqual(nntp.isReply, false, 'a client command')
    assert.strictEqual(nntp.command, 'GROUP')
    assert.strictEqual(nntp.argument, 'misc.test')
    assert.strictEqual(nntp.replyCode, 0, 'commands have no reply code')
    // The message field re-encodes byte-perfect (verbatim guarantee).
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), LoadPacket('nntp/command').hex)
})

// Crafted server replies: a single-line status reply (`211 ...`) is parsed into replyCode/replyText, and a
// multi-line reply (4th char '-') sets isMultiline. Because the message is re-emitted verbatim the whole
// packet round-trips byte-for-byte in every case.
test('NNTP replies: reply metadata + byte-perfect round-trip', async (): Promise<void> => {
    // A GROUP success reply: '211 1234 3000234 3002322 misc.test\r\n'
    const groupReplyHex: string = Buffer.from('211 1234 3000234 3002322 misc.test\r\n', 'latin1').toString('hex')
    const group: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 119, dstport: 54321}},
        {id: 'nntp', data: {message: groupReplyHex}}
    ])
    const decodedGroup: CodecDecodeResult[] = await codec.decode(group.packet)
    AssertLayers(decodedGroup, ['eth', 'ipv4', 'tcp', 'nntp'])
    const groupNntp: any = Layer(decodedGroup, 'nntp').data
    assert.strictEqual(groupNntp.isReply, true, 'a server reply')
    assert.strictEqual(groupNntp.replyCode, 211)
    assert.strictEqual(groupNntp.isMultiline, false, 'a single-line reply')
    assert.strictEqual(groupNntp.replyText, '1234 3000234 3002322 misc.test')
    assert.strictEqual(groupNntp.command, '', 'replies have no command')
    assert.strictEqual(groupNntp.message, groupReplyHex, 'message kept verbatim')
    assert.strictEqual((await codec.encode(decodedGroup)).packet.toString('hex'), group.packet.toString('hex'))

    // A multi-line reply first line: '100-help text follows\r\n' — the 4th char '-' marks continuation.
    const multiHex: string = Buffer.from('100-help text follows\r\n', 'latin1').toString('hex')
    const multi: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 119, dstport: 54321}},
        {id: 'nntp', data: {message: multiHex}}
    ])
    const decodedMulti: CodecDecodeResult[] = await codec.decode(multi.packet)
    const multiNntp: any = Layer(decodedMulti, 'nntp').data
    assert.strictEqual(multiNntp.isReply, true, 'a server reply')
    assert.strictEqual(multiNntp.replyCode, 100)
    assert.strictEqual(multiNntp.isMultiline, true, 'the 4th char is "-"')
    assert.strictEqual(multiNntp.replyText, 'help text follows')
    assert.strictEqual((await codec.encode(decodedMulti)).packet.toString('hex'), multi.packet.toString('hex'))
})

// Non-NNTP traffic on TCP port 119 must NOT be claimed as NNTP: binary junk, and "HELLO x\r\n" (a leading
// token that is not a known NNTP verb) are both rejected — they fall through to raw and round-trip.
test('NNTP does not claim non-NNTP traffic on port 119', async (): Promise<void> => {
    const junk: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 119}},
        {id: 'raw', data: {data: 'deadbeef00112233'}}
    ])
    const decodedJunk: CodecDecodeResult[] = await AssertRoundTrip(junk.packet)
    AssertLayers(decodedJunk, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decodedJunk.some((l: CodecDecodeResult): boolean => l.id === 'nntp'), 'binary junk on 119 is not NNTP')

    // 'HELLO x\r\n' — a leading token that is not a known NNTP command must be rejected.
    const helloHex: string = Buffer.from('HELLO x\r\n', 'latin1').toString('hex')
    const hello: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 119}},
        {id: 'raw', data: {data: helloHex}}
    ])
    const decodedHello: CodecDecodeResult[] = await AssertRoundTrip(hello.packet)
    assert.ok(!decodedHello.some((l: CodecDecodeResult): boolean => l.id === 'nntp'), '"HELLO" is not an NNTP command')
})

// Regression: NNTP must NOT over-claim sibling US-ASCII line protocols on their own ports. NNTP shares
// verbs (QUIT/HELP/LIST/STAT/…) and the NNN-code reply shape with SMTP/FTP/POP3/IRC, so NNTP is confined
// to the tcp:119/tcp:563 buckets (no heuristicFallback). A `GROUP misc.test\r\n` on port 9999 must decode
// as raw, not nntp.
test('NNTP does not steal sibling text traffic on other ports (no heuristicFallback)', async (): Promise<void> => {
    const groupHex: string = Buffer.from('GROUP misc.test\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 9999}}, // not an NNTP port
        {id: 'raw', data: {data: groupHex}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'nntp'), 'a GROUP line on port 9999 must not be claimed off the tcp:119/563 buckets')
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
})

// A truncated NNTP message (cut mid-line) must decode without throwing and re-encode without throwing; a
// command carrying an argument round-trips byte-perfect (verbatim guarantee).
test('NNTP truncated survives; command with argument round-trips', async (): Promise<void> => {
    const full: Buffer = LoadPacket('nntp/command').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 6))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)

    // An ARTICLE command with a message-id argument (may contain spaces/params) is kept verbatim.
    const articleHex: string = Buffer.from('ARTICLE <45223423@example.com>\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 33333, dstport: 119}},
        {id: 'nntp', data: {message: articleHex}}
    ])
    const roundTripped: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const nntp: any = Layer(roundTripped, 'nntp').data
    assert.strictEqual(nntp.command, 'ARTICLE')
    assert.strictEqual(nntp.argument, '<45223423@example.com>')
    assert.strictEqual(nntp.message, articleHex, 'argument kept verbatim')
})
