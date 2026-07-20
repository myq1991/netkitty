import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// RFB / VNC (RFC 6143) ProtocolVersion handshake on TCP port 5900. The 12-byte "RFB 003.008\n" greeting
// is kept verbatim (byte-perfect) and parsed into display-only metadata.
test('RFB ProtocolVersion handshake: greeting metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rfb/handshake').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'rfb'])
    const rfb: any = Layer(decoded, 'rfb').data
    assert.strictEqual(rfb.isVersionHandshake, true, 'the opening 12-byte version line')
    assert.strictEqual(rfb.versionString, 'RFB 003.008')
    assert.strictEqual(rfb.major, 3)
    assert.strictEqual(rfb.minor, 8)
})

// A post-handshake binary RFB message (crafted) on port 5900: no "RFB " signature, so it is NOT a version
// handshake — the whole payload is kept verbatim as `data` and round-trips byte-for-byte.
test('RFB post-handshake binary message: kept verbatim as data, byte-perfect', async (): Promise<void> => {
    // A FramebufferUpdate-shaped opaque binary blob (message-type byte 0x00 then arbitrary bytes).
    const binHex: string = '00000001000a000a00140014000000ffdeadbeef'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 5900, dstport: 54321}},
        {id: 'rfb', data: {message: binHex}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'rfb'])
    const rfb: any = Layer(decoded, 'rfb').data
    assert.strictEqual(rfb.isVersionHandshake, false, 'binary message is not a version handshake')
    assert.strictEqual(rfb.versionString, 'data', 'non-handshake summary tail')
    assert.strictEqual(rfb.message, binHex, 'binary payload kept verbatim')
})

// The version handshake re-encodes byte-identical: the authoritative `message` field is re-emitted
// verbatim (the parsed major/minor never reconstruct the bytes).
test('RFB version handshake re-encodes verbatim from message', async (): Promise<void> => {
    const greetingHex: string = Buffer.from('RFB 003.008\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 5900, dstport: 54321}},
        {id: 'rfb', data: {message: greetingHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const rfb: any = Layer(decoded, 'rfb').data
    assert.strictEqual(rfb.message, greetingHex, 'greeting kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// Port confinement: an "RFB "-looking payload on a NON-5900 port must NOT be claimed as RFB (no
// heuristicFallback) — it falls through to raw. And a truncated payload on 5900 survives decode/encode.
test('RFB is port-confined to 5900; truncation survives', async (): Promise<void> => {
    // Same greeting bytes, but on port 9999 — never reaches the tcp:5900 bucket, so it stays raw.
    const greetingHex: string = Buffer.from('RFB 003.008\n', 'latin1').toString('hex')
    const offPort: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 9999}},
        {id: 'raw', data: {data: greetingHex}}
    ])
    const decodedOffPort: CodecDecodeResult[] = await AssertRoundTrip(offPort.packet)
    AssertLayers(decodedOffPort, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decodedOffPort.some((l: CodecDecodeResult): boolean => l.id === 'rfb'), '"RFB " off port 5900 is not RFB')

    // A truncated greeting (only the first 5 bytes) on port 5900 must decode and re-encode without throwing.
    const full: Buffer = LoadPacket('rfb/handshake').buffer
    const decodedTrunc: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 7))
    await codec.encode(decodedTrunc)
})

// A different ProtocolVersion (003.003) parses its major/minor correctly.
test('RFB 003.003 handshake parses major 3 minor 3', async (): Promise<void> => {
    const greetingHex: string = Buffer.from('RFB 003.003\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 5900, dstport: 54321}},
        {id: 'rfb', data: {message: greetingHex}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const rfb: any = Layer(decoded, 'rfb').data
    assert.strictEqual(rfb.isVersionHandshake, true)
    assert.strictEqual(rfb.versionString, 'RFB 003.003')
    assert.strictEqual(rfb.major, 3)
    assert.strictEqual(rfb.minor, 3)
})
