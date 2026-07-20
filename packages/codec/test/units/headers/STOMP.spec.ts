import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// The CONNECT frame's verbatim payload (COMMAND line + headers + blank line + NUL), as hex.
const CONNECT_MSG: string = '434f4e4e4543540a6163636570742d76657273696f6e3a312e320a686f73743a73746f6d702e6578616d706c652e636f6d0a6c6f67696e3a61646d696e0a0a00'

// Real-shape STOMP 1.2 CONNECT frame on TCP port 61613 (the ActiveMQ default): the client sends
// "CONNECT\naccept-version:1.2\nhost:stomp.example.com\nlogin:admin\n\n\0". The whole payload is kept
// verbatim (byte-perfect); the COMMAND line is parsed into display-only metadata {command:"CONNECT"}.
test('STOMP CONNECT: command parsed, byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('stomp/connect').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'stomp'])
    const stomp: any = Layer(decoded, 'stomp').data
    assert.strictEqual(stomp.command, 'CONNECT', 'COMMAND line parsed')
    assert.strictEqual(stomp.destination, '', 'a CONNECT frame has no destination header')
    assert.strictEqual(stomp.contentLength, 0, 'no content-length header')
    assert.strictEqual(stomp.message, CONNECT_MSG, 'message holds the whole frame verbatim')
})

// Crafted SEND frame with a destination, content-type and body: "SEND\ndestination:/queue/test\n
// content-type:text/plain\ncontent-length:5\n\nhello\0". A verbatim message is the source of truth and
// round-trips byte-for-byte; the metadata report the parsed command and common headers.
test('STOMP faithfully encodes a crafted SEND with a body (verbatim) and parses its headers', async (): Promise<void> => {
    const payload: string = Buffer.from('SEND\ndestination:/queue/test\ncontent-type:text/plain\ncontent-length:5\n\nhello\x00', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.20', dip: '192.0.2.10', protocol: 6}},
        {id: 'tcp', data: {srcport: 61613, dstport: 51820}},
        {id: 'stomp', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'stomp'])
    const stomp: any = Layer(decoded, 'stomp').data
    assert.strictEqual(stomp.command, 'SEND', 'COMMAND line parsed')
    assert.strictEqual(stomp.destination, '/queue/test', 'destination header parsed')
    assert.strictEqual(stomp.contentType, 'text/plain', 'content-type header parsed')
    assert.strictEqual(stomp.contentLength, 5, 'content-length header parsed')
    assert.strictEqual(stomp.message, payload, 'the byte stream (headers + body + NUL) is kept verbatim')
})

// Port + command confinement (no heuristicFallback): a STOMP-looking frame on a non-61613 port must NOT
// be claimed (it falls through to raw), and a truncated frame on port 61613 must decode without throwing
// and stay re-encodable.
test('STOMP is confined to port 61613; truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 51820, dstport: 9999}}, // not port 61613
        {id: 'raw', data: {data: Buffer.from('CONNECT\naccept-version:1.2\n\n\x00', 'latin1').toString('hex')}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'stomp'), 'STOMP text off port 61613 must not be claimed')

    // A CONNECT frame cut mid-payload on port 61613 must decode without throwing and stay re-encodable.
    const full: Buffer = LoadPacket('stomp/connect').buffer
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 12))
    await codec.encode(survived)
})

// Command gate: a non-STOMP-command payload on port 61613 (whose first line is not a known command) must
// fall through to raw rather than claim an un-decodable text layer.
test('STOMP requires a known command line on port 61613 (non-command text falls to raw)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 61613}},
        {id: 'raw', data: {data: Buffer.from('xyzzy not stomp\r\n', 'latin1').toString('hex')}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'stomp'), 'non-command text on 61613 must not be claimed as STOMP')
})
