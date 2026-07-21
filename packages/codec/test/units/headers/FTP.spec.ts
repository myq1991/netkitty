import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Real captured FTP command on TCP port 21 (RFC 959). The whole message is kept verbatim, so it
// round-trips byte-for-byte, and the first line is parsed into display-only metadata.
test('FTP command: first-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ftp/command').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'ftp'])
    const ftp: any = Layer(decoded, 'ftp').data
    assert.strictEqual(ftp.isReply, false, 'a client command')
    assert.strictEqual(ftp.command, 'USER')
    assert.strictEqual(ftp.argument, 'anonymous')
    assert.strictEqual(ftp.replyCode, 0, 'commands have no reply code')
    // The message field re-encodes byte-perfect (verbatim guarantee).
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), LoadPacket('ftp/command').hex)
})

// A crafted multi-line reply: the first line is parsed into replyCode/isMultiline/replyText, and because
// the message is re-emitted verbatim the whole packet round-trips byte-for-byte.
test('FTP multi-line reply: reply metadata + byte-perfect round-trip', async (): Promise<void> => {
    // '220-Multi\r\n220 Done\r\n'
    const replyHex: string = Buffer.from('220-Multi\r\n220 Done\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 21, dstport: 54321}},
        {id: 'ftp', data: {message: replyHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'ftp'])
    const ftp: any = Layer(decoded, 'ftp').data
    assert.strictEqual(ftp.isReply, true, 'a server reply')
    assert.strictEqual(ftp.replyCode, 220)
    assert.strictEqual(ftp.isMultiline, true, 'the 4th char is "-"')
    assert.strictEqual(ftp.replyText, 'Multi')
    assert.strictEqual(ftp.command, '', 'replies have no command')
    assert.strictEqual(ftp.message, replyHex, 'message kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// Non-FTP traffic on TCP port 21 must NOT be claimed as FTP: binary junk, and "HELLO x\r\n" (a leading
// token that is not a known FTP verb) are both rejected — they fall through to raw and round-trip.
test('FTP does not claim non-FTP traffic on port 21', async (): Promise<void> => {
    const junk: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 21}},
        {id: 'raw', data: {data: 'deadbeef00112233'}}
    ])
    const decodedJunk: CodecDecodeResult[] = await AssertRoundTrip(junk.packet)
    AssertLayers(decodedJunk, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decodedJunk.some((l: CodecDecodeResult): boolean => l.id === 'ftp'), 'binary junk on 21 is not FTP')

    // 'HELLO x\r\n' — a leading token that is not a known FTP command must be rejected.
    const helloHex: string = Buffer.from('HELLO x\r\n', 'latin1').toString('hex')
    const hello: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 21}},
        {id: 'raw', data: {data: helloHex}}
    ])
    const decodedHello: CodecDecodeResult[] = await AssertRoundTrip(hello.packet)
    assert.ok(!decodedHello.some((l: CodecDecodeResult): boolean => l.id === 'ftp'), '"HELLO" is not an FTP command')
})

// Regression: FTP must NOT over-claim sibling US-ASCII line protocols on their own ports. FTP shares
// verbs (USER/PASS/LIST/STAT/QUIT/RETR/…) and the NNN-code reply shape with POP3/SMTP/IRC/NNTP, so FTP
// is confined to the tcp:21 bucket (no heuristicFallback). A POP3 'USER alice' on port 110 must decode
// as raw, not ftp.
test('FTP does not steal POP3/SMTP-style traffic on other ports (no heuristicFallback)', async (): Promise<void> => {
    const pop3Hex: string = Buffer.from('USER alice\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 110}}, // POP3 port
        {id: 'raw', data: {data: pop3Hex}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'ftp'), 'a USER line on port 110 must not be claimed by FTP off the tcp:21 bucket')
    // POP3 (now registered, tcp:110) is the rightful owner of this line — confirming each line protocol
    // is confined to its own port bucket, exactly as the no-heuristicFallback decision intends.
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pop3'])
})

// A truncated FTP message (cut mid-line) must decode without throwing and re-encode without throwing; a
// command carrying an argument round-trips byte-perfect (verbatim guarantee).
test('FTP truncated survives; command with argument round-trips', async (): Promise<void> => {
    const full: Buffer = LoadPacket('ftp/command').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 6))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)

    // A RETR command with a path argument (may contain spaces) is kept verbatim.
    const retrHex: string = Buffer.from('RETR /pub/some file.txt\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 33333, dstport: 21}},
        {id: 'ftp', data: {message: retrHex}}
    ])
    const roundTripped: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const ftp: any = Layer(roundTripped, 'ftp').data
    assert.strictEqual(ftp.command, 'RETR')
    assert.strictEqual(ftp.argument, '/pub/some file.txt')
    assert.strictEqual(ftp.message, retrHex, 'argument kept verbatim')
})
