import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Apache Kafka wire protocol (tcp:9092) ApiVersions v0 request. Length-prefixed frame: MessageSize (BE
// uint32, bytes that follow) + request header apiKey/apiVersion/correlationId + clientId + body (kept as
// payload). Fixture is CONSTRUCTED (protocol-accurate ApiVersions v0 request in a netkitty eth/ipv4/tcp
// envelope).
test('Kafka ApiVersions request: length prefix + request header + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('kafka/request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'kafka'])
    const kafka: any = Layer(decoded, 'kafka').data
    // MessageSize counts the bytes after it: apiKey(2) + apiVersion(2) + correlationId(4) + payload(10) = 18.
    assert.strictEqual(kafka.messageSize, 18, 'MessageSize = bytes that follow the length prefix')
    assert.strictEqual(kafka.apiKey, 18, 'ApiVersions')
    assert.strictEqual(kafka.apiVersion, 0)
    assert.strictEqual(kafka.correlationId, 1)
    // payload = clientId nullable string: length 0x0008 + "netkitty" (6e65746b69747479).
    assert.strictEqual(kafka.payload, '00086e65746b69747479', 'clientId "netkitty" (empty ApiVersions v0 body)')
})

// Crafting: a Metadata request (apiKey 3) with the MessageSize auto-derived from the payload — confirm
// the length prefix lands correctly and the message re-encodes byte-for-byte.
test('Kafka faithfully encodes a crafted Metadata request and auto-derives MessageSize', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 55000, dstport: 9092}},
        {id: 'kafka', data: {
            apiKey: 3, apiVersion: 9, correlationId: 42,
            payload: '0009636f6e73756d65722d31' + '00000000ffffffff01' // clientId "consumer-1" + Metadata body bytes
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'kafka'])
    const kafka: any = Layer(decoded, 'kafka').data
    assert.strictEqual(kafka.apiKey, 3, 'Metadata')
    assert.strictEqual(kafka.apiVersion, 9)
    assert.strictEqual(kafka.correlationId, 42)
    // MessageSize = apiKey(2) + apiVersion(2) + correlationId(4) + payload(21) = 29.
    assert.strictEqual(kafka.messageSize, 29, 'auto-derived MessageSize = 8 + payload bytes')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// MessageSize honor-else-derive, plus pipelining: a MessageSize that bounds the message shorter than the
// captured bytes leaves the trailing bytes (a pipelined second message / trailer) to the codec's
// recursion. Those trailing bytes are too short to be a Kafka header, so they fall through to raw.
test('Kafka MessageSize: honor-else-derive and payload bounded by MessageSize (trailing → raw)', async (): Promise<void> => {
    // Derive: no MessageSize supplied → 8 + payload bytes.
    const derived: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 55000, dstport: 9092}},
        {id: 'kafka', data: {apiKey: 1, apiVersion: 0, correlationId: 7, payload: 'aabbccdd'}} // 4 bytes
    ])
    const derivedKafka: any = Layer(await codec.decode(derived.packet), 'kafka').data
    assert.strictEqual(derivedKafka.messageSize, 12, 'derived MessageSize = 8 header + 4 payload')

    // Honor + pipelining: MessageSize 8 says nothing follows the correlationId (empty payload), but 8 more
    // bytes are present. Those trailing bytes (only 8 → shorter than the 12-byte minimal header) must fall
    // through to raw, and the whole thing must round-trip byte-for-byte.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 55000, dstport: 9092}},
        {id: 'kafka', data: {apiKey: 3, apiVersion: 12, correlationId: 99, messageSize: 8, payload: '00000004deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'kafka', 'raw'])
    const kafka: any = Layer(decoded, 'kafka').data
    assert.strictEqual(kafka.messageSize, 8, 'honored MessageSize (not the captured payload length)')
    assert.strictEqual(kafka.payload, '', 'payload bounded to MessageSize: message ends at offset 4 + 8 = 12')
    assert.strictEqual(Layer(decoded, 'raw').data.data, '00000004deadbeef', 'trailing bytes → raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A TCP/9092 payload with an implausible MessageSize (larger than Kafka's default 100 MiB request cap)
// must fall through to raw — the length prefix is a weak signature, so an absurd length is rejected. A
// truncated Kafka frame must decode without throwing.
test('Kafka rejects an implausible MessageSize on port 9092 (falls through to raw); truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 55000, dstport: 9092}},
        {id: 'raw', data: {data: '7fffffff000300000000002a'}} // MessageSize 0x7fffffff (~2 GiB) — implausible
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'kafka'), 'an implausible MessageSize must not be claimed as Kafka')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('kafka/request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 2))
})

// BE edge: apiKey / apiVersion / correlationId are big-endian. Distinct byte patterns confirm the on-wire
// order and that each decodes to the exact value (no endian swap) and re-encodes byte-for-byte.
test('Kafka apiKey/apiVersion/correlationId are big-endian and round-trip exactly', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 55000, dstport: 9092}},
        {id: 'kafka', data: {apiKey: 0x1234, apiVersion: 0x5678, correlationId: 0x89abcdef, payload: 'ff'}}
    ])
    const hex: string = packet.toString('hex')
    // MessageSize = 8 + 1 = 9 → BE bytes 00000009; then apiKey 1234, apiVersion 5678, correlationId 89abcdef, payload ff.
    const idx: number = hex.indexOf('000000091234567889abcdefff')
    assert.ok(idx >= 0, 'MessageSize + apiKey/apiVersion/correlationId are big-endian on the wire')
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const kafka: any = Layer(decoded, 'kafka').data
    assert.strictEqual(kafka.apiKey, 0x1234)
    assert.strictEqual(kafka.apiVersion, 0x5678)
    assert.strictEqual(kafka.correlationId, 0x89abcdef, 'high-bit correlationId decodes as unsigned uint32')
    assert.strictEqual(kafka.payload, 'ff')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), hex, 'byte-perfect')
})
