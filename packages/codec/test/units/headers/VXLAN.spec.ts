import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'

// Real VXLAN (RFC 7348) on UDP 4789 encapsulating an inner Ethernet frame (IPv6/ICMPv6). The inner
// frame is decoded RECURSIVELY as a fresh eth/ip/… stack — the tunnel showcase for the demux design.
test('VXLAN: 8-byte header + recursive inner Ethernet decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('vxlan/inner-ipv6-icmpv6').buffer)
    // Outer eth/ipv4/udp/vxlan, then the WHOLE inner Ethernet stack decoded again.
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'vxlan', 'eth', 'ipv6', 'ipv6-hopopt', 'icmpv6'])
    const vxlan: any = Layer(decoded, 'vxlan').data
    assert.strictEqual(vxlan.flags, 0x08, 'the I (VNI-valid) flag is set')
    assert.strictEqual(vxlan.vni, 42, '24-bit VXLAN Network Identifier')
    assert.strictEqual(vxlan.reserved1, '000000')
    assert.strictEqual(vxlan.reserved2, '00')
    // The inner Ethernet frame (second 'eth' layer) carries the real inner IPv6 payload.
    const innerEth: CodecDecodeResult = decoded.filter((l: CodecDecodeResult): boolean => l.id === 'eth')[1]
    assert.strictEqual((innerEth.data as any).etherType, '86dd', 'inner EtherType = IPv6')
})

// Negative / crafting: build a VXLAN packet from scratch wrapping a crafted inner Ethernet+ARP frame,
// and confirm the whole nested stack encodes and round-trips.
test('VXLAN faithfully encodes a crafted tunnel over a crafted inner Ethernet/ARP frame', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:01', smac: '00:00:00:00:00:02', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 4789}},
        {id: 'vxlan', data: {flags: 0x08, reserved1: '000000', vni: 4096, reserved2: '00'}},
        // Inner Ethernet frame + ARP request.
        {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: 'aa:bb:cc:dd:ee:ff', etherType: '0806'}},
        {id: 'arp', data: {
            hardware: {type: 1, size: 6}, protocol: {type: '0800', size: 4}, opcode: 1,
            sender: {mac: 'aa:bb:cc:dd:ee:ff', ipv4: '192.168.1.1'},
            target: {mac: '00:00:00:00:00:00', ipv4: '192.168.1.2'}
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'vxlan', 'eth', 'arp'])
    assert.strictEqual((Layer(decoded, 'vxlan').data as any).vni, 4096)
    // The inner ARP decoded correctly through the tunnel.
    assert.strictEqual((Layer(decoded, 'arp').data as any).sender.ipv4, '192.168.1.1')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

test('VXLAN truncated mid inner-frame: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('vxlan/inner-ipv6-icmpv6').buffer
    await AssertDecodeSurvives(full.subarray(0, 55))
})

// A sub-8-byte payload on port 4789 is not VXLAN: it must fall through to raw (bounds by UDP payload).
test('VXLAN does not claim a sub-8-byte payload', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 4789}},
        {id: 'raw', data: {data: '0800000000'}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'raw'])
})
