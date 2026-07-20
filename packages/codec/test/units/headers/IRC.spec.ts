import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Real captured IRC command on TCP port 6667 (RFC 1459 / RFC 2812). The whole message is kept verbatim, so
// it round-trips byte-for-byte, and the first line is parsed into display-only metadata.
test('IRC command: first-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('irc/command').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'irc'])
    const irc: any = Layer(decoded, 'irc').data
    assert.strictEqual(irc.command, 'NICK')
    assert.strictEqual(irc.prefix, '', 'an unprefixed client command')
    assert.strictEqual(irc.params, 'alice')
    assert.strictEqual(irc.isNumeric, false, 'NICK is a verb, not a numeric reply')
    // The message field re-encodes byte-perfect (verbatim guarantee).
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), LoadPacket('irc/command').hex)
})

// Crafted IRC messages: a prefixed server numeric reply parses into prefix/command/params with
// isNumeric=true, and an unprefixed client PRIVMSG parses with an empty prefix. Because the message is
// re-emitted verbatim, both whole packets round-trip byte-for-byte.
test('IRC server numeric + client PRIVMSG: metadata + byte-perfect round-trip', async (): Promise<void> => {
    // ':server 001 alice :Welcome\r\n' — a prefixed server welcome (numeric reply 001).
    const srvHex: string = Buffer.from(':server 001 alice :Welcome\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 6667, dstport: 54321}},
        {id: 'irc', data: {message: srvHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'irc'])
    const srv: any = Layer(decoded, 'irc').data
    assert.strictEqual(srv.prefix, 'server')
    assert.strictEqual(srv.command, '001')
    assert.strictEqual(srv.isNumeric, true, 'a 3-digit numeric reply')
    assert.strictEqual(srv.params, 'alice :Welcome')
    assert.strictEqual(srv.message, srvHex, 'message kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))

    // 'PRIVMSG #chan :hi\r\n' — an unprefixed client message (no source prefix).
    const msgHex: string = Buffer.from('PRIVMSG #chan :hi\r\n', 'latin1').toString('hex')
    const priv: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 6667}},
        {id: 'irc', data: {message: msgHex}}
    ])
    const decodedPriv: CodecDecodeResult[] = await AssertRoundTrip(priv.packet)
    const privData: any = Layer(decodedPriv, 'irc').data
    assert.strictEqual(privData.command, 'PRIVMSG')
    assert.strictEqual(privData.prefix, '', 'a client message has no prefix')
    assert.strictEqual(privData.isNumeric, false)
})

// Non-IRC traffic on TCP port 6667 must NOT be claimed as IRC: binary junk, and "HELLO x\r\n" (a leading
// token that is not a known IRC command, nor a prefixed message) are both rejected — they fall to raw.
test('IRC does not claim non-IRC traffic on port 6667', async (): Promise<void> => {
    const junk: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 6667}},
        {id: 'raw', data: {data: 'deadbeef00112233'}}
    ])
    const decodedJunk: CodecDecodeResult[] = await AssertRoundTrip(junk.packet)
    AssertLayers(decodedJunk, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decodedJunk.some((l: CodecDecodeResult): boolean => l.id === 'irc'), 'binary junk on 6667 is not IRC')

    // 'HELLO x\r\n' — a leading token that is not a known IRC command must be rejected.
    const helloHex: string = Buffer.from('HELLO x\r\n', 'latin1').toString('hex')
    const hello: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 6667}},
        {id: 'raw', data: {data: helloHex}}
    ])
    const decodedHello: CodecDecodeResult[] = await AssertRoundTrip(hello.packet)
    assert.ok(!decodedHello.some((l: CodecDecodeResult): boolean => l.id === 'irc'), '"HELLO" is not an IRC command')
})

// Port-confinement regression: IRC must NOT be recognized off its port buckets (no heuristicFallback).
// IRC shares verbs (USER/QUIT/LIST) with FTP/POP3/SMTP, so an IRC-looking 'NICK alice' line on a
// non-6667/6697 port (here 9999) must decode as raw, not irc — this locks in the no-heuristicFallback design.
test('IRC does not steal a NICK line off its port buckets (no heuristicFallback)', async (): Promise<void> => {
    const nickHex: string = Buffer.from('NICK alice\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 9999}}, // NOT an IRC port
        {id: 'raw', data: {data: nickHex}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'irc'), 'a NICK line on port 9999 must not be claimed off the tcp:6667/tcp:6697 buckets')
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
})

// A truncated IRC message (cut mid-line) must decode without throwing and re-encode without throwing; a
// PRIVMSG carrying a `:trailing` argument round-trips byte-perfect (verbatim guarantee).
test('IRC truncated survives; PRIVMSG with :trailing round-trips', async (): Promise<void> => {
    const full: Buffer = LoadPacket('irc/command').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 4))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)

    // A PRIVMSG with a trailing message (the ' :' arg spanning spaces) is kept verbatim.
    const trailHex: string = Buffer.from('PRIVMSG #chan :hello there\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 33333, dstport: 6667}},
        {id: 'irc', data: {message: trailHex}}
    ])
    const roundTripped: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const irc: any = Layer(roundTripped, 'irc').data
    assert.strictEqual(irc.command, 'PRIVMSG')
    assert.strictEqual(irc.params, '#chan :hello there', 'the :trailing argument is kept in params')
    assert.strictEqual(irc.message, trailHex, 'trailing kept verbatim')
})
