import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// GRE (RFC 2784) over IP protocol 47 with Protocol Type 0x0800 tunnels a BARE inner IPv4 packet. The
// protocolType drives the ethertype demux to IPv4 (which accepts a 'gre' parent), NOT EthernetII.
test('GRE over IPv4: base header + inner IPv4 (typed-tunnel dispatch) + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('gre/ipv4-inner').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'gre', 'ipv4', 'icmp'])
    const gre: any = Layer(decoded, 'gre').data
    assert.strictEqual(gre.protocolType, '0800', 'inner is IPv4')
    assert.strictEqual(gre.flags.checksum, false)
    assert.strictEqual(gre.flags.key, false)
    assert.strictEqual(gre.flags.version, 0, 'GRE version 0')
    assert.ok(!decoded.slice(3).some((l: CodecDecodeResult): boolean => l.id === 'eth'), 'no fabricated inner Ethernet layer')
})

// GRE with Key + Sequence Number flags (RFC 2890) and Protocol Type 0x6558 (Transparent Ethernet
// Bridging) tunnels a full inner Ethernet frame, which recurses through EthernetII (guarded to TEB).
test('GRE TEB with Key + Sequence: optional fields + recursive inner Ethernet + byte-perfect', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('gre/teb-keyed-seq').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'gre', 'eth', 'ipv4', 'icmp'])
    const gre: any = Layer(decoded, 'gre').data
    assert.strictEqual(gre.protocolType, '6558', 'Transparent Ethernet Bridging')
    assert.strictEqual(gre.flags.key, true, 'Key present')
    assert.strictEqual(gre.flags.sequence, true, 'Sequence present')
    assert.strictEqual(gre.keyValue, '0000007b', 'Key value')
    assert.strictEqual(gre.sequenceNumber, 1, 'Sequence number')
})

// Crafting: build a GRE frame with the Checksum flag set — the codec honors the given checksum verbatim
// (a faithful executor may carry any checksum, valid or not) and round-trips.
test('GRE faithfully encodes a crafted Checksum-flagged header (checksum honored, not recomputed)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 47}},
        {id: 'gre', data: {
            flags: {checksum: true, routing: false, key: false, sequence: false, strictRoute: false, recur: 0, reserved0: 0, version: 0},
            protocolType: '0800', checksum: 0xabcd, reserved1: '0000'
        }},
        {id: 'ipv4', data: {sip: '192.168.9.1', dip: '192.168.9.2', protocol: 17}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'gre', 'ipv4'])
    const gre: any = Layer(decoded, 'gre').data
    assert.strictEqual(gre.flags.checksum, true)
    assert.strictEqual(gre.checksum, 0xabcd, 'checksum honored verbatim, not recomputed')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// An unknown Protocol Type (not 0x6558/0x0800/0x86dd) must NOT be mislabeled as an inner Ethernet frame
// (the EthernetII gre guard) — its payload falls through to RawData.
test('GRE with an unknown protocol type does not fabricate an inner Ethernet layer', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 47}},
        {id: 'gre', data: {flags: {checksum: false, routing: false, key: false, sequence: false, strictRoute: false, recur: 0, reserved0: 0, version: 0}, protocolType: '9999'}},
        {id: 'raw', data: {data: '45000011deadbeef'}} // payload that starts 0x45 (would look like IPv4)
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'gre', 'raw'])
    assert.ok(!decoded.slice(3).some((l: CodecDecodeResult): boolean => l.id === 'eth' || l.id === 'ipv4'),
        'unknown protocol type must not spawn a fabricated eth/ipv4 inner layer')
})

test('GRE truncated mid inner-frame: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('gre/teb-keyed-seq').buffer
    await AssertDecodeSurvives(full.subarray(0, 30))
})
