import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Real captured POP3 command on TCP port 110 (RFC 1939). The whole message is kept verbatim, so it
// round-trips byte-for-byte, and the first line is parsed into display-only metadata.
test('POP3 command: first-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('pop3/command').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pop3'])
    const pop3: any = Layer(decoded, 'pop3').data
    assert.strictEqual(pop3.isReply, false, 'a client command')
    assert.strictEqual(pop3.command, 'USER')
    assert.strictEqual(pop3.argument, 'alice')
    assert.strictEqual(pop3.status, '', 'commands have no status indicator')
    // The message field re-encodes byte-perfect (verbatim guarantee).
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), LoadPacket('pop3/command').hex)
})

// Crafted POP3 replies: the first line is parsed into status/replyText, and because the message is
// re-emitted verbatim the whole packet round-trips byte-for-byte. POP3 uses `+OK`/`-ERR` (not a code).
test('POP3 reply: +OK / -ERR status metadata + byte-perfect round-trip', async (): Promise<void> => {
    // '+OK POP3 server ready\r\n'
    const okHex: string = Buffer.from('+OK POP3 server ready\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 110, dstport: 54321}},
        {id: 'pop3', data: {message: okHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pop3'])
    const pop3: any = Layer(decoded, 'pop3').data
    assert.strictEqual(pop3.isReply, true, 'a server reply')
    assert.strictEqual(pop3.status, '+OK')
    assert.strictEqual(pop3.replyText, 'POP3 server ready')
    assert.strictEqual(pop3.command, '', 'replies have no command')
    assert.strictEqual(pop3.message, okHex, 'message kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))

    // '-ERR bad\r\n' — a failure reply.
    const errHex: string = Buffer.from('-ERR bad\r\n', 'latin1').toString('hex')
    const err: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 110, dstport: 54321}},
        {id: 'pop3', data: {message: errHex}}
    ])
    const decodedErr: CodecDecodeResult[] = await AssertRoundTrip(err.packet)
    const pop3Err: any = Layer(decodedErr, 'pop3').data
    assert.strictEqual(pop3Err.isReply, true, 'a server reply')
    assert.strictEqual(pop3Err.status, '-ERR')
    assert.strictEqual(pop3Err.replyText, 'bad')
})

// Non-POP3 traffic on TCP port 110 must NOT be claimed as POP3: binary junk, and "HELLO x\r\n" (a leading
// token that is not a known POP3 verb, nor a +OK/-ERR status) are both rejected — they fall to raw.
test('POP3 does not claim non-POP3 traffic on port 110', async (): Promise<void> => {
    const junk: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 110}},
        {id: 'raw', data: {data: 'deadbeef00112233'}}
    ])
    const decodedJunk: CodecDecodeResult[] = await AssertRoundTrip(junk.packet)
    AssertLayers(decodedJunk, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decodedJunk.some((l: CodecDecodeResult): boolean => l.id === 'pop3'), 'binary junk on 110 is not POP3')

    // 'HELLO x\r\n' — a leading token that is not a known POP3 command must be rejected.
    const helloHex: string = Buffer.from('HELLO x\r\n', 'latin1').toString('hex')
    const hello: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 110}},
        {id: 'raw', data: {data: helloHex}}
    ])
    const decodedHello: CodecDecodeResult[] = await AssertRoundTrip(hello.packet)
    assert.ok(!decodedHello.some((l: CodecDecodeResult): boolean => l.id === 'pop3'), '"HELLO" is not a POP3 command')
})

// Port-confinement regression: POP3 must NOT be recognized off its port buckets (no heuristicFallback).
// POP3 shares verbs (USER/PASS/STAT/LIST/RETR/QUIT) with FTP, so a POP3-looking 'USER alice' line on a
// non-110/995 port (here 9999) must decode as raw, not pop3 — this locks in the no-heuristicFallback design.
test('POP3 does not steal a USER line off its port buckets (no heuristicFallback)', async (): Promise<void> => {
    const userHex: string = Buffer.from('USER alice\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 9999}}, // NOT a POP3 port
        {id: 'raw', data: {data: userHex}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'pop3'), 'a USER line on port 9999 must not be claimed off the tcp:110/tcp:995 buckets')
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
})

// A truncated POP3 message (cut mid-line) must decode without throwing and re-encode without throwing; a
// command carrying an argument (RETR 1) round-trips byte-perfect (verbatim guarantee).
test('POP3 truncated survives; command with argument round-trips', async (): Promise<void> => {
    const full: Buffer = LoadPacket('pop3/command').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 4))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)

    // A RETR command with a numeric argument is kept verbatim.
    const retrHex: string = Buffer.from('RETR 1\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 33333, dstport: 110}},
        {id: 'pop3', data: {message: retrHex}}
    ])
    const roundTripped: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const pop3: any = Layer(roundTripped, 'pop3').data
    assert.strictEqual(pop3.command, 'RETR')
    assert.strictEqual(pop3.argument, '1')
    assert.strictEqual(pop3.message, retrHex, 'argument kept verbatim')
})
