import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Shared lower layers for crafted frames on the memcached port bucket (tcp:11211).
const ETH = {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}}
const IPV4 = {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}}

// Build a Memcached binary message (24-byte header + body) as a hex string, for raw-payload pipelining.
function binaryMessage(opcode: number, bodyHex: string): string {
    const bodyLen: number = bodyHex.length / 2
    const header: Buffer = Buffer.alloc(24)
    header.writeUInt8(0x80, 0)          // magic: request
    header.writeUInt8(opcode, 1)        // opcode
    header.writeUInt16BE(bodyLen, 2)    // keyLength (whole body treated as key here)
    header.writeUInt32BE(bodyLen, 8)    // totalBodyLength
    return header.toString('hex') + bodyHex
}

// Real captured Memcached TEXT `get foo\r\n` command on TCP port 11211. The whole payload is kept verbatim,
// so it round-trips byte-for-byte, and the leading token is parsed into the display-only `command` field.
test('Memcached text get: leading-token metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('memcached/get').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'memcached'])
    const mc: any = Layer(decoded, 'memcached').data
    assert.strictEqual(mc.isBinary, false, 'a text command, not the binary protocol')
    assert.strictEqual(mc.command, 'get')
    assert.strictEqual(codec.summary(decoded), 'Memcached get')
    // The message field re-encodes byte-perfect (verbatim guarantee).
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), LoadPacket('memcached/get').hex)
})

// A crafted BINARY GET request (magic 0x80, opcode 0x00). The 24-byte header is structured into editable
// fields and re-encodes byte-identical; crucially the 8-byte CAS survives as a hex string (never a JS
// Number, which would lose precision above 2^53).
test('Memcached binary GET: structured header + byte-identical re-encode, 8-byte CAS preserved as hex', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 44444, dstport: 11211}},
        {id: 'memcached', data: {
            isBinary: true, magic: 0x80, opcode: 0x00, keyLength: 3, extrasLength: 0, dataType: 0,
            status: 0, totalBodyLength: 3, opaque: 0x12345678, cas: 'ffeeddccbbaa9988', body: '666f6f'
        }}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'memcached'])
    const mc: any = Layer(decoded, 'memcached').data
    assert.strictEqual(mc.isBinary, true)
    assert.strictEqual(mc.magic, 0x80)
    assert.strictEqual(mc.opcode, 0x00)
    assert.strictEqual(mc.totalBodyLength, 3)
    assert.strictEqual(mc.opaque, 0x12345678)
    assert.strictEqual(mc.cas, 'ffeeddccbbaa9988', '8-byte CAS kept verbatim as hex (no Number precision loss)')
    assert.strictEqual(mc.body, '666f6f')
    assert.strictEqual(codec.summary(decoded), 'Memcached binary op=0')
})

// A crafted TEXT `set` command with an inline data block. The whole payload is kept verbatim (the CR-LF
// framing and data bytes are preserved), so it round-trips byte-for-byte; the leading token is 'set'.
test('Memcached text set: verbatim byte-perfect + leading token', async (): Promise<void> => {
    const setHex: string = Buffer.from('set key 0 0 5\r\nhello\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 55555, dstport: 11211}},
        {id: 'memcached', data: {message: setHex}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'memcached'])
    const mc: any = Layer(decoded, 'memcached').data
    assert.strictEqual(mc.isBinary, false)
    assert.strictEqual(mc.command, 'set')
    assert.strictEqual(mc.message, setHex, 'the inline data block is kept verbatim')
})

// Port confinement + robustness: non-Memcached traffic on 11211 falls to raw (unknown leading token),
// truncation survives, and a memcached-looking line off the port bucket (9999) is NOT claimed
// (no heuristicFallback).
test('Memcached: non-memcached on 11211 → raw; truncation survives; off-port confinement', async (): Promise<void> => {
    // 'HELLO x\r\n' — a leading token that is not a known memcached verb, on port 11211, must fall to raw.
    const helloHex: string = Buffer.from('HELLO x\r\n', 'latin1').toString('hex')
    const hello: CodecEncodeResult = await codec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 33333, dstport: 11211}},
        {id: 'raw', data: {data: helloHex}}
    ])
    const decodedHello: CodecDecodeResult[] = await AssertRoundTrip(hello.packet)
    assert.ok(!decodedHello.some((l: CodecDecodeResult): boolean => l.id === 'memcached'), '"HELLO" is not a memcached command')
    AssertLayers(decodedHello, ['eth', 'ipv4', 'tcp', 'raw'])

    // Truncated real get frame (cut mid-payload) must decode without throwing and re-encode without throwing.
    const full: Buffer = LoadPacket('memcached/get').buffer
    const decodedTrunc: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 3))
    await codec.encode(decodedTrunc)

    // A real 'get foo' line on a NON-memcached port (9999) must not be claimed off the tcp:11211 bucket.
    const getHex: string = Buffer.from('get foo\r\n', 'latin1').toString('hex')
    const offPort: CodecEncodeResult = await codec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 12345, dstport: 9999}},
        {id: 'raw', data: {data: getHex}}
    ])
    const decodedOff: CodecDecodeResult[] = await AssertRoundTrip(offPort.packet)
    assert.ok(!decodedOff.some((l: CodecDecodeResult): boolean => l.id === 'memcached'), 'a get line on port 9999 must not be claimed (no heuristicFallback)')
    AssertLayers(decodedOff, ['eth', 'ipv4', 'tcp', 'raw'])
})

// Binary totalBodyLength bound: two pipelined binary messages in one TCP segment. The first memcached
// header bounds its body by totalBodyLength; the trailing second message is left to the codec's recursion
// (its parent is now memcached, not tcp, so memcached does not chain) and becomes raw. Round-trips exactly.
test('Memcached binary: body bounded by totalBodyLength, pipelined trailing → raw', async (): Promise<void> => {
    const first: string = binaryMessage(0x00, '666f6f') // GET, 3-byte body
    const second: string = binaryMessage(0x01, '')      // SET, empty body — the pipelined trailing message
    const {packet}: CodecEncodeResult = await codec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 44444, dstport: 11211}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'memcached', 'raw'])
    const mc: any = Layer(decoded, 'memcached').data
    assert.strictEqual(mc.isBinary, true)
    assert.strictEqual(mc.totalBodyLength, 3)
    assert.strictEqual(mc.body, '666f6f', 'body is bounded to totalBodyLength, not the trailing message')
})
