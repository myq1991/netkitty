import {test} from 'node:test'
import assert from 'node:assert'
import {AssertLayers, Layer} from '../../lib/RoundTrip'
import {WebSocket} from '../../../src/lib/codec/headers/WebSocket'
import {Codec} from '../../../src/lib/codec/Codec'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// WebSocket is decode-as-only (its stream is selected by a prior HTTP Upgrade, which a single-packet
// codec cannot track), so it is exercised with a codec that explicitly includes it.
const wsCodec: Codec = new Codec([WebSocket])

const ETH = {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}}
const IPV4 = {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}}

// A masked client text frame (FIN, opcode 1, MASK set, 4-byte masking key) round-trips byte-for-byte;
// the masked payload is kept verbatim (not unmasked, which would change the bytes).
test('WebSocket masked client text frame round-trips byte-perfect', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await wsCodec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 50000, dstport: 8080}},
        {id: 'websocket', data: {fin: true, opcode: 1, mask: true, payloadLen: 2, maskingKey: '37fa213d', payload: '7f9c'}}
    ])
    const decoded: CodecDecodeResult[] = await wsCodec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'websocket'])
    const ws: any = Layer(decoded, 'websocket').data
    assert.strictEqual(ws.fin, true, 'FIN set')
    assert.strictEqual(ws.opcode, 1, 'text frame')
    assert.strictEqual(ws.mask, true, 'client frames are masked')
    assert.strictEqual(ws.maskingKey, '37fa213d', 'masking key verbatim')
    assert.strictEqual(ws.payload, '7f9c', 'masked payload kept verbatim')
    assert.strictEqual((await wsCodec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// An extended-length (126) unmasked server binary frame: the 2-byte extended length is used and the
// frame round-trips byte-for-byte.
test('WebSocket extended-length (126) unmasked frame round-trips', async (): Promise<void> => {
    const payload: string = 'ab'.repeat(130) // 130 bytes -> needs the 16-bit extended length
    const {packet}: CodecEncodeResult = await wsCodec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 8080, dstport: 50000}},
        {id: 'websocket', data: {fin: true, opcode: 2, mask: false, payloadLen: 126, extendedPayloadLength: '0082', payload: payload}}
    ])
    const decoded: CodecDecodeResult[] = await wsCodec.decode(packet)
    const ws: any = Layer(decoded, 'websocket').data
    assert.strictEqual(ws.payloadLen, 126, '7-bit length is the 126 sentinel')
    assert.strictEqual(ws.extendedPayloadLength, '0082', '16-bit extended length = 130')
    assert.strictEqual(ws.mask, false, 'server frames are unmasked')
    assert.strictEqual(ws.payload, payload, '130-byte payload verbatim')
    assert.strictEqual((await wsCodec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A control frame (ping) round-trips; and over-claim guard: the DEFAULT codec (no WebSocket) must never
// decode a websocket layer — it falls through to raw.
test('WebSocket ping frame round-trips; default codec never claims a WebSocket frame', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await wsCodec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 50000, dstport: 8080}},
        {id: 'websocket', data: {fin: true, opcode: 9, mask: true, payloadLen: 0, maskingKey: 'deadbeef', payload: ''}}
    ])
    const decoded: CodecDecodeResult[] = await wsCodec.decode(packet)
    assert.strictEqual((Layer(decoded, 'websocket').data as any).opcode, 9, 'ping opcode')
    assert.strictEqual((await wsCodec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')

    const defaultDecoded: CodecDecodeResult[] = await new Codec().decode(packet)
    assert.ok(!defaultDecoded.some((l: CodecDecodeResult): boolean => l.id === 'websocket'), 'default codec must not auto-claim WebSocket')

    // Truncated frame survives decode without throwing.
    const truncated: CodecDecodeResult[] = await wsCodec.decode(packet.subarray(0, packet.length - 3))
    assert.ok(Array.isArray(truncated), 'truncated frame survives decode')
})
