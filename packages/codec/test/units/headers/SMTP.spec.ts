import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Real captured SMTP command on TCP port 25 (RFC 5321). The whole message is kept verbatim, so it
// round-trips byte-for-byte, and the first line is parsed into display-only metadata.
test('SMTP command: first-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('smtp/command').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'smtp'])
    const smtp: any = Layer(decoded, 'smtp').data
    assert.strictEqual(smtp.isReply, false, 'a client command')
    assert.strictEqual(smtp.command, 'EHLO')
    assert.strictEqual(smtp.argument, 'example.com')
    assert.strictEqual(smtp.replyCode, 0, 'commands have no reply code')
    // The message field re-encodes byte-perfect (verbatim guarantee).
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), LoadPacket('smtp/command').hex)
})

// A crafted multi-line reply: the first line is parsed into replyCode/isMultiline/replyText, and because
// the message is re-emitted verbatim the whole packet round-trips byte-for-byte.
test('SMTP multi-line reply: reply metadata + byte-perfect round-trip', async (): Promise<void> => {
    // '250-STARTTLS\r\n250 HELP\r\n'
    const replyHex: string = Buffer.from('250-STARTTLS\r\n250 HELP\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 25, dstport: 54321}},
        {id: 'smtp', data: {message: replyHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'smtp'])
    const smtp: any = Layer(decoded, 'smtp').data
    assert.strictEqual(smtp.isReply, true, 'a server reply')
    assert.strictEqual(smtp.replyCode, 250)
    assert.strictEqual(smtp.isMultiline, true, 'the 4th char is "-"')
    assert.strictEqual(smtp.replyText, 'STARTTLS')
    assert.strictEqual(smtp.command, '', 'replies have no command')
    assert.strictEqual(smtp.message, replyHex, 'message kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// Non-SMTP traffic on TCP port 25 must NOT be claimed as SMTP: binary junk, and "HELLO x\r\n" (a leading
// token that is not a known SMTP verb) are both rejected — they fall through to raw and round-trip.
test('SMTP does not claim non-SMTP traffic on port 25', async (): Promise<void> => {
    const junk: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 25}},
        {id: 'raw', data: {data: 'deadbeef00112233'}}
    ])
    const decodedJunk: CodecDecodeResult[] = await AssertRoundTrip(junk.packet)
    AssertLayers(decodedJunk, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decodedJunk.some((l: CodecDecodeResult): boolean => l.id === 'smtp'), 'binary junk on 25 is not SMTP')

    // 'HELLO x\r\n' — a leading token that is not a known SMTP command must be rejected.
    const helloHex: string = Buffer.from('HELLO x\r\n', 'latin1').toString('hex')
    const hello: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 25}},
        {id: 'raw', data: {data: helloHex}}
    ])
    const decodedHello: CodecDecodeResult[] = await AssertRoundTrip(hello.packet)
    assert.ok(!decodedHello.some((l: CodecDecodeResult): boolean => l.id === 'smtp'), '"HELLO" is not an SMTP command')
})

// Regression: SMTP must NOT over-claim sibling US-ASCII line protocols on their own ports. SMTP shares
// verbs (HELO/QUIT/NOOP/HELP/AUTH/…) and the NNN-code reply shape with FTP/POP3/IRC/NNTP, so SMTP is
// confined to the tcp:25/tcp:587 buckets (no heuristicFallback). An IRC 'QUIT\r\n' on port 6667 must
// decode as raw, not smtp.
test('SMTP does not steal FTP/IRC-style traffic on other ports (no heuristicFallback)', async (): Promise<void> => {
    const ircHex: string = Buffer.from('QUIT\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 6667}}, // IRC port
        {id: 'raw', data: {data: ircHex}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'smtp'), 'a QUIT line on port 6667 must not be claimed by SMTP off the tcp:25/587 buckets')
    // IRC (now registered, tcp:6667) is the rightful owner of this line — confirming each line protocol is
    // confined to its own port bucket, exactly as the no-heuristicFallback decision intends.
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'irc'])
})

// A truncated SMTP message (cut mid-line) must decode without throwing and re-encode without throwing; a
// command carrying an argument round-trips byte-perfect (verbatim guarantee).
test('SMTP truncated survives; command with argument round-trips', async (): Promise<void> => {
    const full: Buffer = LoadPacket('smtp/command').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 6))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)

    // A MAIL FROM command with an address argument (may contain spaces/params) is kept verbatim.
    const mailHex: string = Buffer.from('MAIL FROM:<alice@example.com> SIZE=1024\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 33333, dstport: 25}},
        {id: 'smtp', data: {message: mailHex}}
    ])
    const roundTripped: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const smtp: any = Layer(roundTripped, 'smtp').data
    assert.strictEqual(smtp.command, 'MAIL')
    assert.strictEqual(smtp.argument, 'FROM:<alice@example.com> SIZE=1024')
    assert.strictEqual(smtp.message, mailHex, 'argument kept verbatim')
})
