import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Spec-accurate Rlogin startup message (RFC 1282) on TCP port 513: the client sends the four null-separated
// strings "\0jdoe\0root\0xterm/38400\0". The whole payload is kept verbatim (byte-perfect); when it opens
// with 0x00 the leading fields are parsed into display-only metadata {isStartup, clientUser, serverUser,
// terminalType}.
test('Rlogin startup: null-separated fields + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rlogin/startup').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'rlogin'])
    const rlogin: any = Layer(decoded, 'rlogin').data
    assert.strictEqual(rlogin.isStartup, true, 'the payload opens with a 0x00 byte → startup message')
    assert.strictEqual(rlogin.clientUser, 'jdoe', 'first null-separated field is the client user')
    assert.strictEqual(rlogin.serverUser, 'root', 'second null-separated field is the server user')
    assert.strictEqual(rlogin.terminalType, 'xterm/38400', 'third field is the terminal-type/speed')
    assert.strictEqual(
        rlogin.message,
        '006a646f6500726f6f7400787465726d2f333834303000',
        'message holds the whole startup payload verbatim'
    )
})

// A crafted startup message re-encodes byte-identical from the `message` field — the display fields are
// never used to reconstruct the bytes. Here a different user/terminal proves the verbatim path.
test('Rlogin crafted startup re-encodes byte-identical (verbatim)', async (): Promise<void> => {
    const payload: string = Buffer.from('\0alice\0dbadmin\0vt100/9600\0', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49820, dstport: 513}},
        {id: 'rlogin', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'rlogin'])
    const rlogin: any = Layer(decoded, 'rlogin').data
    assert.strictEqual(rlogin.isStartup, true, 'opens with 0x00')
    assert.strictEqual(rlogin.clientUser, 'alice', 'client user parsed for display')
    assert.strictEqual(rlogin.serverUser, 'dbadmin', 'server user parsed for display')
    assert.strictEqual(rlogin.terminalType, 'vt100/9600', 'terminal-type/speed parsed for display')
    assert.strictEqual(rlogin.message, payload, 'the startup bytes are kept verbatim')
})

// Byte-stream phase: after the startup exchange the connection is unframed terminal data with no leading
// null. Such a payload is still Rlogin (kept verbatim, byte-perfect) and the display metadata report
// isStartup false with empty fields — proving the fields are honored-else-empty, never fabricated.
test('Rlogin byte-stream data (no leading null): verbatim, not a startup', async (): Promise<void> => {
    const payload: string = Buffer.from('Last login: Mon\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 513, dstport: 49820}},
        {id: 'rlogin', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'rlogin'])
    const rlogin: any = Layer(decoded, 'rlogin').data
    assert.strictEqual(rlogin.isStartup, false, 'no leading 0x00 → not a startup message')
    assert.strictEqual(rlogin.clientUser, '', 'byte-stream phase has no parsed client user')
    assert.strictEqual(rlogin.serverUser, '', 'byte-stream phase has no parsed server user')
    assert.strictEqual(rlogin.terminalType, '', 'byte-stream phase has no parsed terminal type')
    assert.strictEqual(rlogin.message, payload, 'the byte stream is kept verbatim')
})

// Port confinement (no heuristicFallback): a leading-null payload on a non-513 port must NOT be claimed as
// Rlogin — it falls through to raw. And a startup message truncated mid-field on port 513 must decode
// without throwing and remain re-encodable.
test('Rlogin is confined to port 513; truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49820, dstport: 9999}}, // not port 513
        {id: 'raw', data: {data: '006a646f6500726f6f7400'}} // looks like an Rlogin startup, but off-port
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'rlogin'), 'leading null off port 513 must not be claimed by Rlogin')

    // A startup cut mid-field on port 513 must decode without throwing and remain re-encodable.
    const full: Buffer = LoadPacket('rlogin/startup').buffer
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 6))
    await codec.encode(survived)
})

// Protocol edge: the server's success reply is a single 0x00 byte (it opens with a null, so isStartup is
// true, but every startup field is empty). That degenerate startup shape still round-trips byte-for-byte.
test('Rlogin server 0x00 ack: lone null round-trips, empty fields', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 513, dstport: 49820}},
        {id: 'rlogin', data: {message: '00'}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'rlogin'])
    const rlogin: any = Layer(decoded, 'rlogin').data
    assert.strictEqual(rlogin.isStartup, true, 'a lone 0x00 opens with a null → treated as a startup shape')
    assert.strictEqual(rlogin.clientUser, '', 'no client user in the lone-null ack')
    assert.strictEqual(rlogin.serverUser, '', 'no server user in the lone-null ack')
    assert.strictEqual(rlogin.message, '00', 'the single ack byte is kept verbatim')
})
