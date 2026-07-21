import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// The verbatim payload of the fixture: "gorets:1|c\nglork:320|ms" (a counter + a timer).
const PAYLOAD_HEX: string = Buffer.from('gorets:1|c\nglork:320|ms', 'latin1').toString('hex')

// StatsD (udp:8125) text line protocol — the whole datagram is kept verbatim as `message`; the first
// metric line is parsed into display-only metadata. The frame must round-trip byte-for-byte.
test('StatsD metrics: message verbatim + first-metric metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('statsd/metrics').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'statsd'])
    const statsd: any = Layer(decoded, 'statsd').data
    assert.strictEqual(statsd.message, PAYLOAD_HEX, 'whole datagram kept verbatim as hex')
    assert.strictEqual(statsd.metricName, 'gorets', 'first metric name')
    assert.strictEqual(statsd.metricValue, '1', 'first metric value')
    assert.strictEqual(statsd.metricType, 'c', 'first metric type (counter)')
    assert.strictEqual(statsd.sampleRate, '', 'no sampling rate present')
})

// Crafting: a single gauge with a sampling-rate tag ("api.latency:42|g|@0.5"). The datagram is authored
// purely from the verbatim `message` field and must re-encode byte-identically; the parsed metadata
// (populated on decode) must reflect the first — and only — metric line.
test('StatsD faithfully encodes a crafted datagram from the verbatim message', async (): Promise<void> => {
    const line: string = 'api.latency:42|g|@0.5'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.20', dip: '192.0.2.10', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 8125}},
        {id: 'statsd', data: {message: Buffer.from(line, 'latin1').toString('hex')}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'statsd'])
    const statsd: any = Layer(decoded, 'statsd').data
    assert.strictEqual(statsd.metricName, 'api.latency', 'metric name')
    assert.strictEqual(statsd.metricValue, '42', 'metric value')
    assert.strictEqual(statsd.metricType, 'g', 'metric type (gauge)')
    assert.strictEqual(statsd.sampleRate, '0.5', 'sampling rate tag parsed')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a non-metric-shaped payload on udp/8125 must NOT be claimed as StatsD (no colon+pipe
// signature) and must fall through to raw; and a truncated StatsD datagram must survive decode.
test('StatsD rejects a non-metric payload on port 8125, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 51000, dstport: 8125}},
        // arbitrary bytes with no "name:value|type" signature — must not be claimed as StatsD
        {id: 'raw', data: {data: '01020304aabbccdd'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'statsd'), 'non-metric payload must not be claimed as StatsD')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('statsd/metrics').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 5))
})
