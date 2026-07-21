import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Megaco/H.248 text encoding (RFC 3525, udp:2944) — a Transaction Request carrying a Notify command.
// The whole message is kept verbatim (byte-perfect); the header line is parsed for display.
test('Megaco Notify: header line parsed + verbatim byte-perfect round-trip', async (): Promise<void> => {
    const fixture: ReturnType<typeof LoadPacket> = LoadPacket('megaco/notify')
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(fixture.buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'megaco'])
    const megaco: any = Layer(decoded, 'megaco').data
    assert.strictEqual(megaco.startToken, 'MEGACO', 'start token')
    assert.strictEqual(megaco.version, '1', 'protocol version')
    assert.strictEqual(megaco.messageId, '[123.123.123.4]:55555', 'message identifier')
    // The verbatim message reproduces the entire UDP payload as hex.
    const udp: any = Layer(decoded, 'udp').data
    assert.ok(typeof megaco.message === 'string' && megaco.message.length > 0, 'message kept verbatim as hex')
    assert.ok(megaco.message.startsWith('4d4547'), 'message begins with "MEG" bytes')
    assert.strictEqual(udp.dstport, 2944, 'well-known Megaco text port')
})

// Crafting: encode a Megaco message from scratch on udp:2944. The verbatim message is written back
// byte-for-byte, and decode re-parses the header line — a full editor round-trip.
test('Megaco faithfully encodes a crafted message and re-parses its header line', async (): Promise<void> => {
    const text: string = 'MEGACO/1 [10.0.0.1]:2944\r\nTransaction = 50 {\r\n\tContext = - {\r\n\t\tServiceChange = ROOT {\r\n\t\t\tServices {Method=Restart}\r\n\t\t}\r\n\t}\r\n}\r\n'
    const messageHex: string = Buffer.from(text, 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 2944, dstport: 2944}},
        {id: 'megaco', data: {message: messageHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'megaco'])
    const megaco: any = Layer(decoded, 'megaco').data
    assert.strictEqual(megaco.startToken, 'MEGACO', 'start token re-parsed')
    assert.strictEqual(megaco.version, '1', 'version re-parsed')
    assert.strictEqual(megaco.messageId, '[10.0.0.1]:2944', 'message identifier re-parsed')
    assert.strictEqual(megaco.message, messageHex, 'message preserved verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// The short-form start token "!" (RFC 3525 compact encoding) must also be recognized on the Megaco port.
test('Megaco recognizes the "!" short-form start token', async (): Promise<void> => {
    const text: string = '!/1 [10.0.0.1]:2944\r\nT=1{C=-{SC=ROOT{SV{MT=RS}}}}\r\n'
    const messageHex: string = Buffer.from(text, 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 2944, dstport: 2944}},
        {id: 'megaco', data: {message: messageHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'megaco'])
    const megaco: any = Layer(decoded, 'megaco').data
    assert.strictEqual(megaco.startToken, '!', 'short-form start token')
    assert.strictEqual(megaco.version, '1', 'version re-parsed from short form')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a non-Megaco UDP:2944 payload (no MEGACO/ or !/ header) must NOT be claimed as Megaco; it
// falls through to raw. And a truncated Megaco frame must survive decode without throwing.
test('Megaco rejects non-Megaco payload on port 2944, and truncation survives', async (): Promise<void> => {
    // Arbitrary non-signature bytes that do not collide with any registered content heuristic.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 2944}},
        {id: 'raw', data: {data: '9a3b7c04d5e6f7081122'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'megaco'), 'non-Megaco payload must not be claimed')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('megaco/notify').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 8))
})
