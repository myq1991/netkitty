import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Elasticsearch transport (tcp:9300) request — 19-byte fixed header ('ES' magic + message length +
// request id + status + version) + a minimal variable-header body. Must round-trip byte-for-byte.
test('Elasticsearch request: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('elasticsearch/request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'elasticsearch'])
    const es: any = Layer(decoded, 'elasticsearch').data
    assert.strictEqual(es.magic, '4553', "'ES' magic")
    assert.strictEqual(es.messageLength, 22, 'bytes after the length field (requestId+status+version+body)')
    assert.strictEqual(es.requestId, '0000000000000001', 'request id 1 (8-byte, kept verbatim)')
    assert.strictEqual(es.status, 0, 'request, uncompressed, no error')
    assert.strictEqual(es.version, 8080099, 'transport version 8.8.0')
    assert.strictEqual(es.body, '000000060000000000', 'variable header (header size 6, empty maps/features/action)')
})

// Crafting: a minimal message with an empty body and the Message Length auto-computed from the fixed
// fields (requestId 8 + status 1 + version 4 = 13). The minimal well-formed message must re-encode
// byte-identically.
test('Elasticsearch faithfully encodes a crafted empty-body message and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.2', dip: '10.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 9300, dstport: 51000}},
        {id: 'elasticsearch', data: {magic: '4553', requestId: '00000000000000ff', status: 1, version: 8080099}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'elasticsearch'])
    const es: any = Layer(decoded, 'elasticsearch').data
    assert.strictEqual(es.status, 1, 'response status flag')
    assert.strictEqual(es.messageLength, 13, 'auto-computed Length = 13 (fixed fields only, empty body)')
    assert.strictEqual(es.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted message supplies an explicit Message Length — it must be honored
// verbatim (not overwritten by the derived value) so a message that carries any Length round-trips.
test('Elasticsearch honors an explicitly supplied Message Length (does not derive over it)', async (): Promise<void> => {
    // body is 4 bytes => derived Length would be 17; supply 99 to prove it is honored, not derived.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 9300}},
        {id: 'elasticsearch', data: {magic: '4553', messageLength: 99, requestId: '0000000000000007', status: 0, version: 8080099, body: 'deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const es: any = Layer(decoded, 'elasticsearch').data
    assert.strictEqual(es.messageLength, 99, 'supplied Length honored')
    // A lying (too-large) Length is clamped to the bytes actually present, not spawned past the buffer.
    assert.strictEqual(es.body, 'deadbeef', 'body bounded by the captured bytes')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/9300 payload that does not begin with the 'ES' magic must NOT be claimed as
// Elasticsearch (falls through to raw); and a truncated Elasticsearch message must survive decode.
test('Elasticsearch rejects a non-ES payload on port 9300, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 9300}},
        // payload does not start with 'ES' (0x4553) — not the Elasticsearch signature
        {id: 'raw', data: {data: 'deadbeef00000016000000000000000100007b4ae3'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'elasticsearch'), 'non-ES payload must not be claimed')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('elasticsearch/request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})

// Protocol-specific edge: two Elasticsearch messages pipelined in one TCP segment. The first is bounded
// by its Length, so its body does NOT swallow the trailing message; the trailing message falls through
// to raw (a leaf header advances only over its own message and does not re-match itself — its match()
// requires the previous layer to be TCP, which no longer holds). Both directions round-trip byte-perfect.
test('Elasticsearch pipelining: the first message is bounded by its Length; the trailing message falls through to raw', async (): Promise<void> => {
    const first: string = '4553' + '00000016' + '0000000000000001' + '00' + '007b4ae3' + '000000060000000000' // 28 bytes
    const second: string = '4553' + '0000000d' + '0000000000000002' + '00' + '007b4ae3'                       // 19 bytes, empty body
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 9300, dstport: 51000}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'elasticsearch', 'raw'])
    const es: any = Layer(decoded, 'elasticsearch').data
    assert.strictEqual(es.messageLength, 22, 'first message length')
    assert.strictEqual(es.body, '000000060000000000', 'first body bounded by its Length — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing message left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
