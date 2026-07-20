import {test} from 'node:test'
import assert from 'node:assert'
import {Codec} from '../../src/lib/codec/Codec'
import {LoadPacket} from '../lib/Fixtures'
import {writeJsonGolden, loadJsonGolden, goldenExists} from '../lib/Golden'
import {NextLayer, ConsistencyIssue} from '../../src/lib/codec/types/LayerGraph'
import {CodecDecodeResult} from '../../src/lib/codec/types/CodecDecodeResult'
import {CodecSchema} from '../../src/lib/codec/types/CodecSchema'

const codec: Codec = new Codec()

// Regenerate the derived snapshot below with:  UPDATE_GOLDEN=1 node --test dist-test/test/units/LayerGraph.spec.js
const UPDATE: boolean = process.env.UPDATE_GOLDEN === '1'

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
    assert.deepStrictEqual(discriminatorOf('eth', 'lldp'), {field: 'etherType', value: '88cc'})
    assert.deepStrictEqual(discriminatorOf('eth', 'hsr'), {field: 'etherType', value: '892f'})
    // HSR carries its inner frame by the original EtherType — GOOSE (0x88b8) dispatches over an HSR parent.
    assert.deepStrictEqual(discriminatorOf('hsr', 'goose'), {field: 'etherType', value: '88b8'})
    // RawData is always available and carries no discriminator.
    assert.deepStrictEqual(discriminatorOf('eth', 'raw'), null)
})

// Golden SNAPSHOT of the entire demux graph — every parent's ordered child menu AND the discriminator
// {field,value} to reach each child — derived live from the per-schema demuxProducers. This is a
// regenerable snapshot (UPDATE_GOLDEN=1) rather than a hand-maintained literal, so adding a protocol needs
// no edit here: registering it and regenerating the goldens captures its menu + discriminator. A demux
// change that is NOT intended (e.g. the historical ARP-leaf fix, or a port collision) shows up as a
// snapshot diff. The file is test/fixtures/goldens/_layergraph.json.
test('demux graph snapshot: full parent→child menu + discriminators', (): void => {
    const menu: Record<string, string[]> = {}
    const discriminators: Record<string, Record<string, {field: string, value: string | number} | null>> = {}
    for (const codecSchema of codec.CODEC_SCHEMAS as CodecSchema[]) {
        const nexts: NextLayer[] = codec.allowedNextLayers(codecSchema.id)
        menu[codecSchema.id] = nexts.map((n: NextLayer): string => n.id)
        discriminators[codecSchema.id] = {}
        for (const n of nexts) discriminators[codecSchema.id][n.id] = n.discriminator
    }
    const snapshot: {menu: typeof menu, discriminators: typeof discriminators} = {menu, discriminators}
    if (UPDATE) {
        writeJsonGolden('_layergraph', snapshot)
        return
    }
    assert.ok(goldenExists('_layergraph'), 'no _layergraph snapshot — run UPDATE_GOLDEN=1 to create it')
    assert.deepStrictEqual(JSON.parse(JSON.stringify(snapshot)), loadJsonGolden('_layergraph'), 'the demux menu/discriminator graph drifted from its snapshot — run UPDATE_GOLDEN=1 if intended')
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
    // GRE/VRRP/OSPF are carried over IP by protocol number.
    assert.deepStrictEqual(discriminatorOf('ipv4', 'gre'), {field: 'protocol', value: 47})
    assert.deepStrictEqual(discriminatorOf('ipv6', 'gre'), {field: 'nxt', value: 47})
    assert.deepStrictEqual(discriminatorOf('ipv4', 'ospf'), {field: 'protocol', value: 89})
})

test('allowedNextLayers: a genuine leaf layer offers only RawData', (): void => {
    // goose/arp/icmp are true leaves — no demux dimension hangs off them.
    assert.deepStrictEqual(nextIds('goose'), ['raw'])
    assert.deepStrictEqual(nextIds('icmp'), ['raw'])
})

// Representative port-keyed dispatch anchors (the exhaustive per-port map is covered by the snapshot
// above; these pin the semantics: a dual content-heuristic child on 443/2404, and a couple of well-known
// ports, each listed once with a dstport discriminator hint).
test('allowedNextLayers: tcp/udp offer port-keyed children with dstport discriminators', (): void => {
    const tcp: string[] = nextIds('tcp')
    for (const expected of ['tls-handshake', 'IEC104_I_Frame', 'http', 'raw']) {
        assert.ok(tcp.includes(expected), `tcp should offer '${expected}', got ${tcp.join(',')}`)
    }
    assert.deepStrictEqual(discriminatorOf('tcp', 'tls-handshake'), {field: 'dstport', value: 443})
    assert.deepStrictEqual(discriminatorOf('tcp', 'IEC104_I_Frame'), {field: 'dstport', value: 2404})
    assert.deepStrictEqual(discriminatorOf('tcp', 'http'), {field: 'dstport', value: 80})
    assert.deepStrictEqual(discriminatorOf('udp', 'ntp'), {field: 'dstport', value: 123})
    assert.deepStrictEqual(discriminatorOf('udp', 'dns'), {field: 'dstport', value: 53})
    // GENEVE routes its inner frame by protocolType (an EtherType).
    assert.deepStrictEqual(discriminatorOf('geneve', 'ipv4'), {field: 'protocolType', value: '0800'})
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
