import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

const MARKER: string = 'ff'.repeat(16)

// BGP-4 (tcp:179) OPEN message — 19-byte header (all-ones marker + length + type) + OPEN body.
test('BGP OPEN: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('bgp/open').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'bgp'])
    const bgp: any = Layer(decoded, 'bgp').data
    assert.strictEqual(bgp.marker, MARKER, 'all-ones marker')
    assert.strictEqual(bgp.length, 29, 'total message length incl 19-byte header')
    assert.strictEqual(bgp.type, 1, 'OPEN')
    assert.strictEqual(bgp.body, '04fc0000b4c000020100', 'version 4, AS 64512, hold 180, id 192.0.2.1, opt len 0')
})

// Crafting: a KEEPALIVE (type 4, empty body) with the Length auto-computed from the (empty) body — the
// minimal well-formed BGP message must re-encode byte-identically.
test('BGP faithfully encodes a crafted KEEPALIVE and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.2', dip: '192.0.2.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 179}},
        {id: 'bgp', data: {marker: MARKER, type: 4}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'bgp'])
    const bgp: any = Layer(decoded, 'bgp').data
    assert.strictEqual(bgp.type, 4, 'KEEPALIVE')
    assert.strictEqual(bgp.length, 19, 'auto-computed Length = 19 (header only, empty body)')
    assert.strictEqual(bgp.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted NOTIFICATION supplies an explicit Length — it must be honored
// verbatim (not overwritten by the derived value) so a message that carries any Length round-trips.
test('BGP honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    // NOTIFICATION body: error code 6 (Cease), subcode 2, no data => 2 bytes. Length = 19 + 2 = 21.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 179, dstport: 51000}},
        {id: 'bgp', data: {marker: MARKER, length: 21, type: 3, body: '0602'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const bgp: any = Layer(decoded, 'bgp').data
    assert.strictEqual(bgp.type, 3, 'NOTIFICATION')
    assert.strictEqual(bgp.length, 21, 'supplied Length honored')
    assert.strictEqual(bgp.body, '0602', 'Cease / subcode 2')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/179 payload whose 16-byte marker is not all-ones must NOT be claimed as BGP (falls
// through to raw); and a truncated BGP message must survive decode without throwing.
test('BGP rejects a non-all-ones marker on port 179, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 179}},
        // marker is 15 x 0xFF then 0x00 — not the BGP signature
        {id: 'raw', data: {data: 'ffffffffffffffffffffffffffffff00001304'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'bgp'), 'non-all-ones marker must not be claimed as BGP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('bgp/open').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})

// Protocol-specific edge: two BGP messages pipelined in one TCP segment. The first message is bounded
// by its Length, so its body does NOT swallow the trailing message; the trailing bytes fall through to
// raw (a leaf header advances only over its own message and does not re-match itself, matching the
// length-bounded-TCP-payload precedent). Both directions round-trip byte-for-byte.
test('BGP pipelining: the first message is bounded by its Length; the trailing message falls through to raw', async (): Promise<void> => {
    const openBody: string = '04fc0000b4c000020100'                 // 10-byte OPEN body => length 29
    const first: string = MARKER + '001d01' + openBody              // 29-byte OPEN
    const second: string = MARKER + '001304'                        // 19-byte KEEPALIVE
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 179, dstport: 51000}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'bgp', 'raw'])
    const bgp: any = Layer(decoded, 'bgp').data
    assert.strictEqual(bgp.type, 1, 'first is OPEN')
    assert.strictEqual(bgp.body, openBody, 'OPEN body bounded by its Length — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing KEEPALIVE left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
