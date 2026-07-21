import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// RIPng (udp:521) Response — 4-byte fixed header (command/version/reserved) + one 20-byte RTE.
test('RIPng Response: header + RTE array + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ripng/response').buffer)
    AssertLayers(decoded, ['eth', 'ipv6', 'udp', 'ripng'])
    const ripng: any = Layer(decoded, 'ripng').data
    assert.strictEqual(ripng.command, 2, 'Response')
    assert.strictEqual(ripng.version, 1, 'version 1')
    assert.strictEqual(ripng.reserved, 0, 'reserved zero')
    assert.strictEqual(ripng.rtes.length, 1, 'one RTE')
    assert.strictEqual(ripng.rtes[0].prefix, '20010db8000000000000000000000000', 'IPv6 prefix 2001:db8::')
    assert.strictEqual(ripng.rtes[0].routeTag, 0, 'route tag 0')
    assert.strictEqual(ripng.rtes[0].prefixLength, 64, 'prefix length 64')
    assert.strictEqual(ripng.rtes[0].metric, 1, 'metric 1')
})

// Crafting: a Request (command 1) carrying a Next Hop RTE (metric 255, prefix length 0, RFC 2080 §2.1.1)
// followed by a route RTE — both RTEs are carried structurally and the message re-encodes byte-identically.
test('RIPng faithfully encodes a crafted Request with a Next Hop RTE', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '33:33:00:00:00:09', smac: '00:00:00:00:00:01', etherType: '86dd'}},
        {id: 'ipv6', data: {sip: 'fe80::1', dip: 'ff02::9', nxt: 17}},
        {id: 'udp', data: {srcport: 521, dstport: 521}},
        {id: 'ripng', data: {command: 1, version: 1, reserved: 0, rtes: [
            {prefix: '20010db8000000000000000000000001', routeTag: 0, prefixLength: 0, metric: 255},
            {prefix: 'fe800000000000000000000000000002', routeTag: 100, prefixLength: 64, metric: 3}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv6', 'udp', 'ripng'])
    const ripng: any = Layer(decoded, 'ripng').data
    assert.strictEqual(ripng.command, 1, 'Request')
    assert.strictEqual(ripng.rtes.length, 2, 'next-hop RTE + route RTE')
    assert.strictEqual(ripng.rtes[0].metric, 255, 'next-hop RTE metric 255')
    assert.strictEqual(ripng.rtes[0].prefixLength, 0, 'next-hop RTE prefix length 0')
    assert.strictEqual(ripng.rtes[1].routeTag, 100, 'second RTE route tag')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a non-conformant Command / Version on UDP port 521 must NOT be claimed as RIPng (falls
// through to raw); and a truncated RIPng message must survive decode without throwing.
test('RIPng rejects a non-conformant command/version on port 521, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '33:33:00:00:00:09', smac: '00:00:00:00:00:01', etherType: '86dd'}},
        {id: 'ipv6', data: {sip: 'fe80::1', dip: 'ff02::9', nxt: 17}},
        {id: 'udp', data: {srcport: 521, dstport: 521}},
        // command 9 / version 2 — not a RIPng signature
        {id: 'raw', data: {data: '0902000020010db8000000000000000000000000000040ff'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'ripng'), 'non-conformant header must not be claimed as RIPng')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('ripng/response').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 5))
})

// Bounding: a trailing RTE fragment shorter than 20 bytes (e.g. Ethernet padding) is not absorbed — the
// walk is bounded by the UDP payload length so the message round-trips exactly.
test('RIPng bounds the RTE walk by the UDP payload and survives a short trailing fragment', async (): Promise<void> => {
    const full: Buffer = LoadPacket('ripng/response').buffer
    // Append 6 stray bytes after the frame — a partial RTE; must not be read into an RTE.
    const padded: Buffer = Buffer.concat([full, Buffer.from('aabbccddeeff', 'hex')])
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(padded)
    const ripng: CodecDecodeResult | undefined = decoded.find((l: CodecDecodeResult): boolean => l.id === 'ripng')
    if (ripng) assert.strictEqual((ripng.data as any).rtes.length, 1, 'trailing partial RTE not absorbed')
})
