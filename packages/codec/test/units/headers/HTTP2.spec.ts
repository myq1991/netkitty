import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

const PREFACE: string = '505249202a20485454502f322e300d0a0d0a534d0d0a0d0a'

// HTTP/2 cleartext (h2c, tcp:80) connection-preface packet — the 24-byte preface + first SETTINGS frame.
test('HTTP2 preface + SETTINGS: preface, frame header + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('http2/preface-settings').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'http2'])
    const h2: any = Layer(decoded, 'http2').data
    assert.strictEqual(h2.preface, PREFACE, 'connection preface')
    assert.strictEqual(h2.length, 12, 'SETTINGS payload length')
    assert.strictEqual(h2.type, 4, 'SETTINGS')
    assert.strictEqual(h2.flags, 0, 'no flags')
    assert.strictEqual(h2.reserved, 0, 'reserved bit unset')
    assert.strictEqual(h2.streamId, 0, 'connection-control stream 0')
    assert.strictEqual(h2.payload, '00030000006400040000ffff', 'MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=65535')
})

// Crafting: a preface + a minimal empty PING-ish frame (type 6, streamId 0) with the Length auto-computed
// from the (empty) payload — the smallest well-formed preface packet must re-encode byte-identically.
test('HTTP2 faithfully encodes a crafted preface frame and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 54321, dstport: 80}},
        {id: 'http2', data: {type: 6, streamId: 0}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'http2'])
    const h2: any = Layer(decoded, 'http2').data
    assert.strictEqual(h2.preface, PREFACE, 'default preface emitted')
    assert.strictEqual(h2.type, 6, 'PING')
    assert.strictEqual(h2.length, 0, 'auto-computed Length = 0 (empty payload)')
    assert.strictEqual(h2.payload, '', 'empty payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length + reserved/streamId fidelity: a crafted HEADERS frame supplies an explicit
// Length and a non-zero Stream Identifier — both must be honored verbatim and round-trip.
test('HTTP2 honors an explicit Length and preserves the Stream Identifier', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 54321, dstport: 80}},
        {id: 'http2', data: {length: 4, type: 1, flags: 5, streamId: 1, payload: '82848d41'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const h2: any = Layer(decoded, 'http2').data
    assert.strictEqual(h2.type, 1, 'HEADERS')
    assert.strictEqual(h2.flags, 5, 'END_STREAM | END_HEADERS')
    assert.strictEqual(h2.length, 4, 'supplied Length honored')
    assert.strictEqual(h2.streamId, 1, 'client-initiated stream 1 preserved')
    assert.strictEqual(h2.payload, '82848d41', 'HPACK block kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/80 payload that is NOT the h2c preface must NOT be claimed as HTTP2 (falls through to
// raw); and a truncated preface packet must survive decode without throwing.
test('HTTP2 rejects a non-preface payload on port 80, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 54321, dstport: 80}},
        // non-signature bytes (not the "PRI * HTTP/2.0" preface, not any registered content heuristic)
        {id: 'raw', data: {data: '0102030405060708090a0b0c0d0e0f10111213141516171819'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'http2'), 'non-preface payload must not be claimed as HTTP2')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('http2/preface-settings').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})

// Protocol-specific edge: a second frame pipelined after the first in the same segment. The first frame
// is bounded by its Length, so its payload does NOT swallow the trailing frame; the trailing bytes fall
// through to raw (the trailing frame carries no preface, so HTTP2 does not re-match it). Round-trips.
test('HTTP2 pipelining: the first frame is bounded by its Length; the trailing frame falls through to raw', async (): Promise<void> => {
    const frame1: string = '000000040100000000'                 // SETTINGS ACK: len 0, type 4, flags 1 (ACK), stream 0
    const frame2: string = '0000080600000000000102030405060708' // PING: len 8, type 6, stream 0, 8-byte opaque payload
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 54321, dstport: 80}},
        {id: 'raw', data: {data: PREFACE + frame1 + frame2}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'http2', 'raw'])
    const h2: any = Layer(decoded, 'http2').data
    assert.strictEqual(h2.type, 4, 'first frame is SETTINGS')
    assert.strictEqual(h2.length, 0, 'first frame length (ACK, empty payload)')
    assert.strictEqual(h2.flags, 1, 'ACK flag')
    assert.strictEqual(h2.payload, '', 'first frame empty — trailing frame not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, frame2, 'trailing PING frame left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
