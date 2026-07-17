import {test} from 'node:test'
import assert from 'node:assert'
import {Codec} from '../../lib/codec/Codec'
import {LoadPacket} from '../lib/Fixtures'
import {NextLayer, ConsistencyIssue} from '../../lib/codec/types/LayerGraph'
import {CodecDecodeResult} from '../../lib/codec/types/CodecDecodeResult'

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

test('allowedNextLayers: ipv4 uses protocol, ipv6 uses nxt', (): void => {
    assert.ok(nextIds('ipv4').includes('tcp'))
    assert.ok(nextIds('ipv6').includes('tcp'))
    assert.deepStrictEqual(discriminatorOf('ipv4', 'tcp'), {field: 'protocol', value: 6})
    assert.deepStrictEqual(discriminatorOf('ipv6', 'tcp'), {field: 'nxt', value: 6})
    assert.deepStrictEqual(discriminatorOf('ipv4', 'udp'), {field: 'protocol', value: 17})
})

test('allowedNextLayers: a leaf/transport layer offers only RawData (heuristic children not in the demux graph)', (): void => {
    assert.deepStrictEqual(nextIds('tcp'), ['raw'])
})

// 2b: the discriminator to set when adding a child (RawData / heuristic children return null).
test('childDiscriminator returns the parent field+value to make a child follow', (): void => {
    assert.deepStrictEqual(codec.childDiscriminator('eth', 'ipv6'), {field: 'etherType', value: '86dd'})
    assert.deepStrictEqual(codec.childDiscriminator('ipv6', 'tcp'), {field: 'nxt', value: 6})
    assert.strictEqual(codec.childDiscriminator('eth', 'raw'), null)
    assert.strictEqual(codec.childDiscriminator('tcp', 'tls-handshake'), null)
})

// 2c: consistency detection — advisory, never blocks encode.
test('checkConsistency: a well-formed stack reports no issues', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('tls/clienthello').buffer)
    assert.deepStrictEqual(codec.checkConsistency(decoded), [])
})

test('checkConsistency: a lying parent discriminator is flagged with an aligning suggestion', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('tls/clienthello').buffer)
    // eth says IPv6 but the next layer is IPv4.
    ;(decoded.find((l: CodecDecodeResult): boolean => l.id === 'eth')!.data as any).etherType = '86dd'
    const issues: ConsistencyIssue[] = codec.checkConsistency(decoded)
    assert.strictEqual(issues.length, 1)
    assert.strictEqual(issues[0].parentId, 'eth')
    assert.strictEqual(issues[0].childId, 'ipv4')
    assert.strictEqual(issues[0].actual, '86dd')
    assert.deepStrictEqual(issues[0].suggestion, {field: 'etherType', value: '0800'})
})

test('checkConsistency: a wrong ip.protocol is flagged and suggests the correct protocol number', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('tls/clienthello').buffer)
    ;(decoded.find((l: CodecDecodeResult): boolean => l.id === 'ipv4')!.data as any).protocol = 17
    const issues: ConsistencyIssue[] = codec.checkConsistency(decoded)
    assert.strictEqual(issues.length, 1)
    assert.deepStrictEqual(issues[0].suggestion, {field: 'protocol', value: 6})
})
