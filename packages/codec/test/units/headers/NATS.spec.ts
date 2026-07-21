import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// NATS (tcp:4222) server INFO message — the whole US-ASCII segment kept verbatim; the control line
// parsed for display into operation + arguments. decode→encode must reproduce the original bytes.
test('NATS INFO: verbatim message + parsed control line + byte-perfect round-trip', async (): Promise<void> => {
    const fixture: ReturnType<typeof LoadPacket> = LoadPacket('nats/info')
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(fixture.buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'nats'])
    const nats: any = Layer(decoded, 'nats').data
    assert.strictEqual(nats.operation, 'INFO', 'leading operation verb parsed for display')
    // The message is the whole TCP payload verbatim (hex), the authoritative source of truth.
    const payloadHex: string = fixture.hex.slice((14 + 20 + 20) * 2)
    assert.strictEqual(nats.message, payloadHex, 'message is the whole segment verbatim')
    assert.ok(nats.controlArguments.startsWith('{'), 'INFO arguments are the JSON options object')
    assert.ok(nats.controlArguments.includes('"port":4222'), 'JSON options carried on the control line')
})

// Crafting: a standalone PING keep-alive ("PING\r\n") — a minimal well-formed NATS message with no
// arguments must be recognized and re-encoded byte-identically from its verbatim message.
test('NATS faithfully encodes a crafted PING and round-trips byte-perfect', async (): Promise<void> => {
    const ping: string = Buffer.from('PING\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.2', dip: '10.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 4222}},
        {id: 'nats', data: {message: ping}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'nats'])
    const nats: any = Layer(decoded, 'nats').data
    assert.strictEqual(nats.operation, 'PING', 'standalone PING operation')
    assert.strictEqual(nats.controlArguments, '', 'PING has no control arguments')
    assert.strictEqual(nats.message, ping, 'message preserved verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Crafting: a client PUB with a binary-safe payload body. The whole message (control line + payload +
// trailing CRLF) is kept verbatim, so even a payload containing arbitrary bytes round-trips exactly and
// the parsed operation is the case-insensitive verb.
test('NATS keeps a PUB message (control line + payload) verbatim', async (): Promise<void> => {
    // "PUB events.order 5\r\nHELLO\r\n"
    const pub: string = Buffer.from('PUB events.order 5\r\nHELLO\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 4222}},
        {id: 'nats', data: {message: pub}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const nats: any = Layer(decoded, 'nats').data
    assert.strictEqual(nats.operation, 'PUB', 'PUB operation')
    assert.strictEqual(nats.controlArguments, 'events.order 5', 'control-line arguments (subject + #bytes)')
    assert.strictEqual(nats.message, pub, 'control line + payload kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/4222 payload with no NATS operation signature must NOT be claimed as NATS (falls
// through to raw); and a truncated NATS message must survive decode without throwing.
test('NATS rejects non-signature payload on port 4222, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 4222}},
        // arbitrary unsigned bytes — no NATS verb, and no other content heuristic
        {id: 'raw', data: {data: '9c3f7a01b2c4'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'nats'), 'non-signature payload must not be claimed as NATS')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('nats/info').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})
