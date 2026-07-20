import {test} from 'node:test'
import assert from 'node:assert'
import {Codec} from '../../src/lib/codec/Codec'
import {LoadPacket} from '../lib/Fixtures'
import {NextLayer, ConsistencyIssue} from '../../src/lib/codec/types/LayerGraph'
import {CodecDecodeResult} from '../../src/lib/codec/types/CodecDecodeResult'
import {CodecSchema} from '../../src/lib/codec/types/CodecSchema'

const codec: Codec = new Codec()

function nextIds(parentId: string): string[] {
    return codec.allowedNextLayers(parentId).map((n: NextLayer): string => n.id)
}
function discriminatorOf(parentId: string, childId: string): {field: string, value: string | number} | null {
    const next: NextLayer | undefined = codec.allowedNextLayers(parentId).find((n: NextLayer): boolean => n.id === childId)
    return next ? next.discriminator : null
}

// 2a: the parent→child menu, derived by reversing the demux dispatch table.
test('allowedNextLayers: eth offers ethertype-keyed children plus RawData', (): void => {
    const ids: string[] = nextIds('eth')
    for (const expected of ['ipv4', 'ipv6', 'arp', 'vlan', 'raw']) {
        assert.ok(ids.includes(expected), `eth should be able to be followed by '${expected}', got ${ids.join(',')}`)
    }
    assert.deepStrictEqual(discriminatorOf('eth', 'ipv4'), {field: 'etherType', value: '0800'})
    assert.deepStrictEqual(discriminatorOf('eth', 'ipv6'), {field: 'etherType', value: '86dd'})
    // RawData is always available and carries no discriminator.
    assert.deepStrictEqual(discriminatorOf('eth', 'raw'), null)
})

// Golden snapshot of the full parent→child menu, derived from the per-schema demuxProducers
// declarations. Records the ARP-leaf fix: with producers declared per schema (not inferred from a
// schema property named 'protocol'), ARP no longer wrongly offers ipproto children — it is a leaf.
test('allowedNextLayers golden: full parent→child menu (records the ARP leaf fix)', (): void => {
    const menu: Record<string, string[]> = {}
    for (const codecSchema of codec.CODEC_SCHEMAS as CodecSchema[]) {
        menu[codecSchema.id] = codec.allowedNextLayers(codecSchema.id).map((n: NextLayer): string => n.id)
    }
    assert.deepStrictEqual(menu, {
        eth: ['arp', 'goose', 'sv', 'ipv4', 'ipv6', 'vlan', 'raw'],
        vlan: ['arp', 'goose', 'sv', 'ipv4', 'ipv6', 'vlan', 'raw'],
        ipv4: ['icmp', 'ipv6-hopopt', 'icmpv6', 'tcp', 'udp', 'raw'],
        ipv6: ['icmp', 'ipv6-hopopt', 'icmpv6', 'tcp', 'udp', 'raw'],
        'ipv6-hopopt': ['icmp', 'ipv6-hopopt', 'icmpv6', 'tcp', 'udp', 'raw'],
        arp: ['raw'],
        goose: ['raw'],
        sv: ['raw'],
        icmp: ['raw'],
        icmpv6: ['raw'],
        // tcp gained port-keyed children (TLS on 443, IEC104 on 2404) via the tcpport demux dimension.
        tcp: ['stun', 'tls-alert', 'tls-appdata', 'tls-ccsp', 'tls-handshake', 'tls-heartbeat', 'IEC104_I_Frame', 'IEC104_S_Frame', 'IEC104_U_Frame', 'raw'],
        udp: ['ntp', 'stun', 'dhcp', 'dns', 'snmp', 'mdns', 'dhcpv6', 'tftp', 'llmnr', 'nbns', 'syslog', 'radius', 'vxlan', 'gtp', 'rmcp', 'raw'],
        ntp: ['raw'],
        stun: ['raw'],
        dhcp: ['raw'],
        dns: ['raw'],
        snmp: ['raw'],
        mdns: ['raw'],
        dhcpv6: ['raw'],
        tftp: ['raw'],
        llmnr: ['raw'],
        nbns: ['raw'],
        syslog: ['raw'],
        radius: ['raw'],
        vxlan: ['raw'],
        gtp: ['raw'],
        rmcp: ['raw'],
        'tls-handshake': ['raw'],
        'tls-alert': ['raw'],
        'tls-ccsp': ['raw'],
        'tls-appdata': ['raw'],
        'tls-heartbeat': ['raw'],
        IEC104_I_Frame: ['raw'],
        IEC104_S_Frame: ['raw'],
        IEC104_U_Frame: ['raw'],
        raw: ['raw']
    })
})

// Boundary: ARP is a leaf (declares no demuxProducers). It must not offer any demux child, and a
// real eth+arp packet followed by nothing must not sprout a phantom layer.
test('ARP is a demux leaf: only RawData follows, no phantom child from its protocol field', async (): Promise<void> => {
    assert.deepStrictEqual(nextIds('arp'), ['raw'])
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('arp/baseline').buffer)
    const nonRaw: CodecDecodeResult[] = decoded.filter((l: CodecDecodeResult): boolean => l.id !== 'raw')
    assert.deepStrictEqual(nonRaw.map((l: CodecDecodeResult): string => l.id), ['eth', 'arp'])
    assert.deepStrictEqual(codec.checkConsistency(decoded), [])
})

// Boundary: an unregistered discriminator value (etherType nobody claims) is normal, not an issue,
// when the following layer is RawData.
test('checkConsistency: unregistered etherType followed by raw is not flagged', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('codec/unknown-ethertype').buffer)
    assert.deepStrictEqual(codec.checkConsistency(decoded), [])
})

test('allowedNextLayers: ipv4 uses protocol, ipv6 uses nxt', (): void => {
    assert.ok(nextIds('ipv4').includes('tcp'))
    assert.ok(nextIds('ipv6').includes('tcp'))
    assert.deepStrictEqual(discriminatorOf('ipv4', 'tcp'), {field: 'protocol', value: 6})
    assert.deepStrictEqual(discriminatorOf('ipv6', 'tcp'), {field: 'nxt', value: 6})
    assert.deepStrictEqual(discriminatorOf('ipv4', 'udp'), {field: 'protocol', value: 17})
})

test('allowedNextLayers: a genuine leaf layer offers only RawData', (): void => {
    // goose/arp/icmp are true leaves — no demux dimension hangs off them.
    assert.deepStrictEqual(nextIds('goose'), ['raw'])
    assert.deepStrictEqual(nextIds('icmp'), ['raw'])
})

// M1③b: tcp now offers its port-keyed children (TLS on 443, IEC104 on 2404), each listed once with a
// dstport discriminator hint, plus RawData. udp stays raw-only (no udp protocols registered yet).
test('allowedNextLayers: tcp offers its port-keyed children (TLS/IEC104) plus RawData', (): void => {
    const ids: string[] = nextIds('tcp')
    for (const expected of ['tls-handshake', 'tls-appdata', 'IEC104_I_Frame', 'raw']) {
        assert.ok(ids.includes(expected), `tcp should offer '${expected}', got ${ids.join(',')}`)
    }
    assert.deepStrictEqual(discriminatorOf('tcp', 'tls-handshake'), {field: 'dstport', value: 443})
    assert.deepStrictEqual(discriminatorOf('tcp', 'IEC104_I_Frame'), {field: 'dstport', value: 2404})
    // udp now offers NTP on its well-known port 123.
    assert.deepStrictEqual(nextIds('udp'), ['ntp', 'stun', 'dhcp', 'dns', 'snmp', 'mdns', 'dhcpv6', 'tftp', 'llmnr', 'nbns', 'syslog', 'radius', 'vxlan', 'gtp', 'rmcp', 'raw'])
    assert.deepStrictEqual(discriminatorOf('udp', 'ntp'), {field: 'dstport', value: 123})
    assert.deepStrictEqual(discriminatorOf('udp', 'stun'), {field: 'dstport', value: 3478})
    assert.deepStrictEqual(discriminatorOf('udp', 'dhcp'), {field: 'dstport', value: 67})
    assert.deepStrictEqual(discriminatorOf('udp', 'dns'), {field: 'dstport', value: 53})
    assert.deepStrictEqual(discriminatorOf('udp', 'snmp'), {field: 'dstport', value: 161})
    assert.deepStrictEqual(discriminatorOf('udp', 'mdns'), {field: 'dstport', value: 5353})
    assert.deepStrictEqual(discriminatorOf('udp', 'dhcpv6'), {field: 'dstport', value: 546})
    assert.deepStrictEqual(discriminatorOf('udp', 'tftp'), {field: 'dstport', value: 69})
    assert.deepStrictEqual(discriminatorOf('udp', 'llmnr'), {field: 'dstport', value: 5355})
    assert.deepStrictEqual(discriminatorOf('udp', 'nbns'), {field: 'dstport', value: 137})
    assert.deepStrictEqual(discriminatorOf('udp', 'syslog'), {field: 'dstport', value: 514})
    assert.deepStrictEqual(discriminatorOf('udp', 'radius'), {field: 'dstport', value: 1812})
    assert.deepStrictEqual(discriminatorOf('udp', 'vxlan'), {field: 'dstport', value: 4789})
    assert.deepStrictEqual(discriminatorOf('udp', 'gtp'), {field: 'dstport', value: 2152})
    assert.deepStrictEqual(discriminatorOf('udp', 'rmcp'), {field: 'dstport', value: 623})
})

// 2b: the discriminator to set when adding a child (RawData / heuristic children return null).
test('childDiscriminator returns the parent field+value to make a child follow', (): void => {
    assert.deepStrictEqual(codec.childDiscriminator('eth', 'ipv6'), {field: 'etherType', value: '86dd'})
    assert.deepStrictEqual(codec.childDiscriminator('ipv6', 'tcp'), {field: 'nxt', value: 6})
    assert.strictEqual(codec.childDiscriminator('eth', 'raw'), null)
    // A port-keyed dual child now has a discriminator hint (its well-known port); RawData and
    // not-reachable pairs return null.
    assert.deepStrictEqual(codec.childDiscriminator('tcp', 'tls-handshake'), {field: 'dstport', value: 443})
    assert.strictEqual(codec.childDiscriminator('tcp', 'ipv4'), null)
})

// 2c: consistency detection — advisory, never blocks encode.
test('checkConsistency: a well-formed stack reports no issues', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('tls/clienthello').buffer)
    assert.deepStrictEqual(codec.checkConsistency(decoded), [])
})

test('checkConsistency: a lying parent discriminator is flagged with an aligning suggestion', async (): Promise<void> => {
    // Use eth→arp: arp is a plain demux child (not a heuristic-chain member), so the consistency
    // mechanism applies. (IPv4/IPv6 are now heuristic-chain members — to also decode as bare-IP tunnel
    // inner payloads — so, like TLS/IEC104, a lying eth.etherType above them is deliberately not
    // flagged; that content/tunnel-reachable edge is intentionally silent in the editor.)
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('arp/baseline').buffer)
    // eth says IPv4 (0800) but the next layer is ARP (etherType should be 0806).
    ;(decoded.find((l: CodecDecodeResult): boolean => l.id === 'eth')!.data as any).etherType = '0800'
    const issues: ConsistencyIssue[] = codec.checkConsistency(decoded)
    assert.strictEqual(issues.length, 1)
    assert.strictEqual(issues[0].parentId, 'eth')
    assert.strictEqual(issues[0].childId, 'arp')
    assert.strictEqual(issues[0].actual, '0800')
    assert.deepStrictEqual(issues[0].suggestion, {field: 'etherType', value: '0806'})
})

test('checkConsistency: a wrong ip.protocol is flagged and suggests the correct protocol number', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('tls/clienthello').buffer)
    ;(decoded.find((l: CodecDecodeResult): boolean => l.id === 'ipv4')!.data as any).protocol = 17
    const issues: ConsistencyIssue[] = codec.checkConsistency(decoded)
    assert.strictEqual(issues.length, 1)
    assert.deepStrictEqual(issues[0].suggestion, {field: 'protocol', value: 6})
})
