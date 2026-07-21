import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// GENEVE (RFC 8926) with Protocol Type 0x6558 (Transparent Ethernet Bridging) tunnels a full inner
// Ethernet frame, which recurses through EthernetII (it accepts a 'geneve' parent), like VXLAN.
test('GENEVE TEB: base header + recursive inner Ethernet frame + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('geneve/eth-inner-icmp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'geneve', 'eth', 'ipv4', 'icmp'])
    const geneve: any = Layer(decoded, 'geneve').data
    assert.strictEqual(geneve.version, 0)
    assert.strictEqual(geneve.protocolType, '6558', 'Transparent Ethernet Bridging')
    assert.strictEqual(geneve.vni, 100)
    assert.strictEqual(geneve.optLen, 0, 'no options')
    assert.deepStrictEqual(geneve.options, [], 'no options')
})

// GENEVE with Protocol Type 0x0800 tunnels a BARE inner IPv4 packet (no inner Ethernet). The
// protocolType drives the ethertype demux to IPv4 (which accepts a 'geneve' parent) — NOT EthernetII.
test('GENEVE with IPv4 protocol type decodes a bare inner IPv4 packet (typed-tunnel dispatch)', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('geneve/ipv4-inner-icmp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'geneve', 'ipv4', 'icmp'])
    const geneve: any = Layer(decoded, 'geneve').data
    assert.strictEqual(geneve.protocolType, '0800', 'inner is IPv4, not Ethernet')
    // The inner (second) IPv4 layer is the tunneled packet, dispatched by protocolType not a fabricated eth.
    assert.ok(!decoded.slice(4).some((l: CodecDecodeResult): boolean => l.id === 'eth'), 'no fabricated inner Ethernet layer')
})

// Crafting: build a GENEVE frame carrying a variable-length option and confirm the Opt Len is
// auto-computed and the option round-trips.
test('GENEVE faithfully encodes a crafted option and auto-computes Opt Len', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 6081, dstport: 6081}},
        {id: 'geneve', data: {
            version: 0, oam: false, critical: false, protocolType: '6558', vni: 200,
            options: [{optionClass: 0x0102, type: 0x80, critical: true, reserved: 0, data: 'aabbccdd'}]
        }},
        {id: 'eth', data: {dmac: '11:22:33:44:55:66', smac: 'aa:bb:cc:dd:ee:ff', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.5.1', dip: '192.168.5.2', protocol: 17}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const geneve: any = Layer(decoded, 'geneve').data
    assert.strictEqual(geneve.optLen, 2, 'Opt Len = (4-byte option header + 4-byte data) / 4 = 2')
    assert.strictEqual(geneve.options.length, 1)
    assert.strictEqual(geneve.options[0].optionClass, 0x0102)
    assert.strictEqual(geneve.options[0].data, 'aabbccdd')
    assert.strictEqual(geneve.options[0].critical, true, 'type high bit = critical')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// An unknown Protocol Type (not 0x6558/0x0800/0x86dd) must NOT be mislabeled as an inner Ethernet frame
// (the EthernetII geneve guard) — its payload falls through to RawData.
test('GENEVE with an unknown protocol type does not fabricate an inner Ethernet layer', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 6081, dstport: 6081}},
        {id: 'geneve', data: {version: 0, oam: false, critical: false, protocolType: '9999', vni: 1}},
        {id: 'raw', data: {data: '45000011deadbeef'}} // payload that starts 0x45 (would look like IPv4)
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'geneve', 'raw'])
    assert.ok(!decoded.slice(4).some((l: CodecDecodeResult): boolean => l.id === 'eth' || l.id === 'ipv4'),
        'unknown protocol type must not spawn a fabricated eth/ipv4 inner layer')
})

test('GENEVE truncated mid-header: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('geneve/eth-inner-icmp').buffer
    await AssertDecodeSurvives(full.subarray(0, 44))
})
