import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'

// Real DHCP DISCOVER (client → server, broadcast) captured from dhclient against dnsmasq. RFC 2131.
test('DHCP discover: fixed header + options decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('dhcp/discover').buffer)
    // The BOOTP minimum-size zero padding after the End option falls to the raw catch-all.
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'dhcp', 'raw'])
    const dhcp: any = Layer(decoded, 'dhcp').data
    assert.strictEqual(dhcp.op, 1, 'BOOTREQUEST')
    assert.strictEqual(dhcp.htype, 1, 'Ethernet')
    assert.strictEqual(dhcp.hlen, 6)
    assert.strictEqual(dhcp.hops, 0)
    assert.strictEqual(dhcp.xid, 0x1b7bac6e)
    assert.strictEqual(dhcp.flags, 0, 'unicast (broadcast bit clear)')
    assert.strictEqual(dhcp.ciaddr, '0.0.0.0')
    assert.strictEqual(dhcp.yiaddr, '0.0.0.0')
    assert.strictEqual(dhcp.chaddr, 'ae615653997500000000000000000000', '6-byte MAC + 10 bytes zero padding')
    assert.strictEqual(dhcp.magicCookie, '63825363')
    // Option 53 (DHCP Message Type) = 1 (DISCOVER); option 55 (Parameter Request List); then End (255).
    assert.deepStrictEqual(dhcp.options[0], {code: 53, value: '01'}, 'DHCP Message Type = DISCOVER')
    assert.strictEqual(dhcp.options[dhcp.options.length - 1].code, 255, 'terminated by End')
})

// Real DHCP ACK (server → client). Carries the lease (yiaddr) and many options; no trailing padding.
test('DHCP ack: lease + options decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('dhcp/ack').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'dhcp'])
    const dhcp: any = Layer(decoded, 'dhcp').data
    assert.strictEqual(dhcp.op, 2, 'BOOTREPLY')
    assert.strictEqual(dhcp.xid, 0x1b7bac6e, 'same transaction id as the discover')
    assert.strictEqual(dhcp.yiaddr, '192.168.99.51', 'the leased address')
    assert.strictEqual(dhcp.siaddr, '192.168.99.1', 'the DHCP server')
    assert.deepStrictEqual(dhcp.options[0], {code: 53, value: '05'}, 'DHCP Message Type = ACK')
    // Option 51 (IP Address Lease Time) = 120s = 0x00000078.
    const leaseTime: any = dhcp.options.find((o: any): boolean => o.code === 51)
    assert.strictEqual(leaseTime.value, '00000078')
})

// Negative / crafting: encode is a faithful executor. Craft a BOOTREPLY with the broadcast flag set,
// a hand-built option, and NO End option — the packet is emitted as given and survives a round-trip.
test('DHCP faithfully encodes a crafted reply with the broadcast flag and no End option', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.1', dip: '255.255.255.255', protocol: 17}},
        {id: 'udp', data: {srcport: 67, dstport: 68}},
        {id: 'dhcp', data: {
            op: 2, htype: 1, hlen: 6, hops: 0, xid: 0xdeadbeef, secs: 0, flags: 0x8000,
            ciaddr: '0.0.0.0', yiaddr: '10.0.0.5', siaddr: '10.0.0.1', giaddr: '0.0.0.0',
            chaddr: '001122334455' + '00'.repeat(10), sname: '00'.repeat(64), file: '00'.repeat(128),
            magicCookie: '63825363',
            options: [{code: 53, value: '05'}, {code: 54, value: '0a000001'}]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const dhcp: any = Layer(decoded, 'dhcp').data
    assert.strictEqual(dhcp.op, 2)
    assert.strictEqual(dhcp.flags, 0x8000, 'broadcast flag preserved')
    assert.strictEqual(dhcp.xid, 0xdeadbeef)
    assert.strictEqual(dhcp.yiaddr, '10.0.0.5')
    assert.deepStrictEqual(dhcp.options[0], {code: 53, value: '05'})
    assert.deepStrictEqual(dhcp.options[1], {code: 54, value: '0a000001'})
    // Re-encode reproduces the exact bytes even without an End option.
    const {packet: reencoded}: {packet: Buffer} = await codec.encode(decoded)
    assert.strictEqual(reencoded.toString('hex'), packet.toString('hex'))
})

test('DHCP truncated mid-options: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('dhcp/ack').buffer
    // Cut into the options block (drop the last 20 bytes).
    await AssertDecodeSurvives(full.subarray(0, full.length - 20))
})

// A DHCP message on a non-67/68 port must still be recognized via its magic cookie (heuristicFallback).
test('DHCP is recognized off its well-known ports via the magic cookie', async (): Promise<void> => {
    const original: Buffer = LoadPacket('dhcp/ack').buffer
    const decoded: CodecDecodeResult[] = await codec.decode(original)
    const dhcp: any = Layer(decoded, 'dhcp').data
    // Re-encode onto ports 5067/5068 and confirm it still decodes as DHCP by the cookie.
    const rebuilt: CodecDecodeResult[] = decoded.map((l: CodecDecodeResult): CodecDecodeResult =>
        l.id === 'udp' ? {...l, data: {...(l.data as any), srcport: 5067, dstport: 5068, checksum: 0}} : l)
    const {packet}: {packet: Buffer} = await codec.encode(rebuilt)
    const redecoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(redecoded.some((l: CodecDecodeResult): boolean => l.id === 'dhcp'), 'DHCP recognized off-port via cookie')
    assert.strictEqual((Layer(redecoded, 'dhcp').data as any).yiaddr, dhcp.yiaddr)
})
