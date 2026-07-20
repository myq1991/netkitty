import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Ethernet+IPv4+TCP scaffold for a crafted RESP frame on a chosen TCP port pair.
function frame(srcport: number, dstport: number, messageHex: string): CodecDecodeResult[] {
    return [
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: srcport, dstport: dstport}},
        {id: 'redis', data: {message: messageHex}}
    ] as unknown as CodecDecodeResult[]
}

const hex = (s: string): string => Buffer.from(s, 'latin1').toString('hex')

// Real captured Redis command on TCP port 6379 (RESP array of bulk strings, `SET foo bar`). The whole
// message is kept verbatim, so it round-trips byte-for-byte, and the leading byte / first line is parsed
// into display-only metadata.
test('Redis command: first-byte metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('redis/command').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'redis'])
    const redis: any = Layer(decoded, 'redis').data
    assert.strictEqual(redis.respType, 'array', 'a `*` array frame')
    assert.strictEqual(redis.isRequest, true, 'array framing is a client command')
    assert.strictEqual(redis.command, 'SET', 'first bulk string is the command verb')
    assert.strictEqual(redis.preview, '*3', 'first line up to CRLF')
    // The message field re-encodes byte-perfect (verbatim guarantee).
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), LoadPacket('redis/command').hex)
})

// Crafted RESP2/RESP3 responses: the leading type byte is parsed into respType, and because the message is
// re-emitted verbatim the whole packet round-trips byte-for-byte. Covers simple-string / error / integer /
// bulk-string.
test('Redis responses: leading-byte respType + byte-perfect round-trip', async (): Promise<void> => {
    const cases: {msg: string, respType: string}[] = [
        {msg: '+OK\r\n', respType: 'simple-string'},
        {msg: '-ERR unknown\r\n', respType: 'error'},
        {msg: ':1000\r\n', respType: 'integer'},
        {msg: '$6\r\nfoobar\r\n', respType: 'bulk-string'}
    ]
    for (const c of cases) {
        const {packet}: CodecEncodeResult = await codec.encode(frame(6379, 54321, hex(c.msg)))
        const decoded: CodecDecodeResult[] = await codec.decode(packet)
        AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'redis'])
        const redis: any = Layer(decoded, 'redis').data
        assert.strictEqual(redis.respType, c.respType, `respType for ${JSON.stringify(c.msg)}`)
        assert.strictEqual(redis.isRequest, false, 'a response is not the `*` array shape')
        assert.strictEqual(redis.command, '', 'non-array responses carry no command')
        assert.strictEqual(redis.message, hex(c.msg), 'message kept verbatim')
        // Byte-identical re-encode.
        assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
    }
})

// A GET command (array of bulk strings) parses its first element as the command verb, flags isRequest, and
// round-trips byte-perfect.
test('Redis command parse: `*2 $3 GET $3 foo` → command GET', async (): Promise<void> => {
    const msg: string = '*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n'
    const {packet}: CodecEncodeResult = await codec.encode(frame(40000, 6379, hex(msg)))
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'redis'])
    const redis: any = Layer(decoded, 'redis').data
    assert.strictEqual(redis.respType, 'array')
    assert.strictEqual(redis.isRequest, true)
    assert.strictEqual(redis.command, 'GET')
    assert.strictEqual(redis.message, hex(msg), 'message kept verbatim')
})

// Port-confinement + no-heuristicFallback regression. Non-RESP traffic on 6379 (a leading byte not in the
// type set) falls to raw; AND a RESP-looking `+OK\r\n` on a NON-6379 port (9999) must ALSO fall to raw —
// locking in that the 1-byte RESP signature never joins the global heuristic chain.
test('Redis is confined to tcp:6379 (no heuristicFallback)', async (): Promise<void> => {
    // Non-RESP on 6379: a leading 'X' (0x58) is not a RESP type byte.
    const xHex: string = hex('X not resp\r\n')
    const junk: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 6379}},
        {id: 'raw', data: {data: xHex}}
    ] as unknown as CodecDecodeResult[])
    const decodedJunk: CodecDecodeResult[] = await AssertRoundTrip(junk.packet)
    AssertLayers(decodedJunk, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decodedJunk.some((l: CodecDecodeResult): boolean => l.id === 'redis'), 'non-RESP on 6379 is not Redis')

    // RESP-looking `+OK\r\n` on port 9999 (NOT a Redis port) must decode as raw, not redis.
    const okHex: string = hex('+OK\r\n')
    const offPort: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 9999}}, // NOT a Redis port
        {id: 'raw', data: {data: okHex}}
    ] as unknown as CodecDecodeResult[])
    const decodedOff: CodecDecodeResult[] = await AssertRoundTrip(offPort.packet)
    assert.ok(!decodedOff.some((l: CodecDecodeResult): boolean => l.id === 'redis'), 'a `+OK` line on port 9999 must not be claimed off the tcp:6379 bucket')
    AssertLayers(decodedOff, ['eth', 'ipv4', 'tcp', 'raw'])
})

// A truncated RESP message (cut mid-frame) must decode without throwing and re-encode without throwing; a
// large multi-bulk array round-trips byte-perfect (verbatim guarantee).
test('Redis truncated survives; large multi-bulk array round-trips', async (): Promise<void> => {
    const full: Buffer = LoadPacket('redis/command').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 6))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)

    // A larger MSET command (array of 7 bulk strings) is kept verbatim.
    const big: string = '*7\r\n$4\r\nMSET\r\n$2\r\nk1\r\n$2\r\nv1\r\n$2\r\nk2\r\n$2\r\nv2\r\n$2\r\nk3\r\n$2\r\nv3\r\n'
    const {packet}: CodecEncodeResult = await codec.encode(frame(40001, 6379, hex(big)))
    const roundTripped: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const redis: any = Layer(roundTripped, 'redis').data
    assert.strictEqual(redis.respType, 'array')
    assert.strictEqual(redis.command, 'MSET')
    assert.strictEqual(redis.message, hex(big), 'large array kept verbatim')
})
