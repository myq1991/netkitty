import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, LayerIds, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'

// The eth/ipv4/udp envelope every crafted packet rides on (RIP conventionally uses UDP 520 -> 520,
// responses multicast to 224.0.0.9). Assembled through the encoder so lengths/checksums stay valid.
function envelope(rip: any, extra: any[] = []): any[] {
    return [
        {id: 'eth', data: {dmac: '01:00:5e:00:00:09', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '224.0.0.9', protocol: 17, ttl: 1}},
        {id: 'udp', data: {srcport: 520, dstport: 520}},
        rip,
        ...extra
    ]
}

// Real-shaped RIP v2 response (2 route entries) over UDP 520. tshark's 'rip' dissector agrees with this
// fixture (command 2, version 2, both entries). RFC 2453: 4-byte header + 20-byte route entries.
test('RIP v2 response: field decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rip/response').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rip'])
    const rip: any = Layer(decoded, 'rip').data
    assert.strictEqual(rip.command, 2, 'command 2 = response')
    assert.strictEqual(rip.version, 2, 'RIP version 2')
    assert.strictEqual(rip.reserved, 0, 'reserved must be zero')
    assert.strictEqual(rip.entries.length, 2, 'two route entries decoded')
    assert.strictEqual(rip.entries[0].addressFamily, 2, 'AF_INET')
    assert.strictEqual(rip.entries[0].ipAddress, '192.168.1.0')
    assert.strictEqual(rip.entries[0].subnetMask, '255.255.255.0')
    assert.strictEqual(rip.entries[0].metric, 1)
    assert.strictEqual(rip.entries[1].ipAddress, '10.0.0.0')
    assert.strictEqual(rip.entries[1].subnetMask, '255.0.0.0')
    assert.strictEqual(rip.entries[1].metric, 2)
})

// A crafted single-entry response must re-encode byte-identically (fixed-format symmetry).
test('RIP v2 crafted single-entry response re-encodes byte-identically', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode(envelope(
        {id: 'rip', data: {command: 2, version: 2, reserved: 0, entries: [
            {addressFamily: 2, routeTag: 100, ipAddress: '172.16.0.0', subnetMask: '255.255.0.0', nextHop: '192.168.1.1', metric: 5}
        ]}}
    ))
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rip'])
    const rip: any = Layer(decoded, 'rip').data
    assert.strictEqual(rip.entries.length, 1)
    assert.strictEqual(rip.entries[0].routeTag, 100, 'route tag preserved')
    assert.strictEqual(rip.entries[0].nextHop, '192.168.1.1', 'next hop preserved')
    const re: {packet: Buffer} = await codec.encode(decoded)
    assert.strictEqual(re.packet.toString('hex'), packet.toString('hex'), 'single-entry round-trip byte-identical')
})

// The entry walk is bounded by the UDP payload: a trailing partial entry (< 20 bytes) is NOT consumed by
// RIP but left for the raw layer, and the whole frame still round-trips byte-for-byte.
test('RIP v2 entry walk is payload-bounded; trailing partial entry falls to raw', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode(envelope(
        {id: 'rip', data: {command: 2, version: 2, reserved: 0, entries: [
            {addressFamily: 2, routeTag: 0, ipAddress: '10.1.0.0', subnetMask: '255.255.0.0', nextHop: '0.0.0.0', metric: 4}
        ]}},
        // 3 stray bytes after the single 20-byte entry — shorter than a full entry, so RIP must not claim them.
        [{id: 'raw', data: {data: 'aabbcc'}}]
    ))
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.deepStrictEqual(LayerIds(decoded), ['eth', 'ipv4', 'udp', 'rip', 'raw'], 'trailing 3 bytes become a raw layer')
    const rip: any = Layer(decoded, 'rip').data
    assert.strictEqual(rip.entries.length, 1, 'only the one full entry is walked; the partial 3 bytes are not over-read')
    const re: {packet: Buffer} = await codec.encode(decoded)
    assert.strictEqual(re.packet.toString('hex'), packet.toString('hex'), 'payload-bounded walk round-trips byte-for-byte')
})

// Negative: a non-RIPv2 payload on udp:520 (version 1) must NOT be claimed as RIP — it falls to raw; and
// a truncated RIP frame must decode without throwing.
test('RIP rejects non-v2 version and survives truncation', async (): Promise<void> => {
    // A RIPv1-shaped payload (version = 1) on port 520: 4-byte header + one 20-byte entry.
    const {packet}: {packet: Buffer} = await codec.encode(envelope(
        {id: 'raw', data: {data: '0101' + '00'.repeat(2) + '0002' + '00'.repeat(18)}}
    ))
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!LayerIds(decoded).includes('rip'), 'version 1 is not decoded as RIP v2')
    assert.ok(LayerIds(decoded).includes('raw'), 'non-v2 payload falls to raw')

    // Truncation mid-entry: decode survives.
    const full: Buffer = LoadPacket('rip/response').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 12))
})

// Protocol-specific edge: entries are carried generically, so a RIPv2 authentication entry (addressFamily
// 0xFFFF, RFC 2453 §4.2) and a full-table request (command 1, metric 16 = infinity) round-trip byte-for-byte
// even though the auth data occupies the ip/mask/nexthop/metric slots.
test('RIP v2 authentication entry and metric-16 request round-trip generically', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode(envelope(
        {id: 'rip', data: {command: 1, version: 2, reserved: 0, entries: [
            {addressFamily: 65535, routeTag: 2, ipAddress: '0.0.0.0', subnetMask: '0.0.0.0', nextHop: '0.0.0.0', metric: 0},
            {addressFamily: 0, routeTag: 0, ipAddress: '0.0.0.0', subnetMask: '0.0.0.0', nextHop: '0.0.0.0', metric: 16}
        ]}}
    ))
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rip'])
    const rip: any = Layer(decoded, 'rip').data
    assert.strictEqual(rip.command, 1, 'command 1 = request')
    assert.strictEqual(rip.entries[0].addressFamily, 65535, 'auth entry addressFamily 0xFFFF preserved')
    assert.strictEqual(rip.entries[1].addressFamily, 0, 'AF_UNSPEC full-table request entry')
    assert.strictEqual(rip.entries[1].metric, 16, 'metric 16 = infinity preserved')
})
