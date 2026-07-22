import {test} from 'node:test'
import assert from 'node:assert'
import {CodecDecodeResult} from '@netkitty/codec'
import {canonicalConversationKey, flowOf, hash32, topProtocolOf} from '../../src/indexer/ConversationKey'
import {FrameIndexer} from '../../src/indexer/FrameIndexer'
import {ColumnarIndexStore} from '../../src/stores/ColumnarIndexStore'
import {FrameIndexRecord} from '../../src/types/FrameIndexRecord'

function layer(id: string, data: Record<string, unknown>, protocol: boolean = true): CodecDecodeResult {
    return {id: id, name: id, nickname: id, protocol: protocol, errors: [], data: data as any}
}

function tcpLayers(sip: string, sport: number, dip: string, dport: number): CodecDecodeResult[] {
    return [layer('eth', {}), layer('ipv4', {sip: sip, dip: dip}), layer('tcp', {srcport: sport, dstport: dport})]
}

test('conversation key: flowOf prefers IP+transport, canonical key is direction-independent', (): void => {
    const ab: CodecDecodeResult[] = tcpLayers('10.0.0.1', 1234, '10.0.0.2', 80)
    const ba: CodecDecodeResult[] = tcpLayers('10.0.0.2', 80, '10.0.0.1', 1234)
    const keyAb: string = canonicalConversationKey(flowOf(ab)!)
    const keyBa: string = canonicalConversationKey(flowOf(ba)!)
    assert.strictEqual(keyAb, 'tcp|10.0.0.1:1234|10.0.0.2:80')
    assert.strictEqual(keyAb, keyBa, 'both directions collapse to one key')
})

test('conversation key: falls back to bare IP, then Ethernet MAC', (): void => {
    assert.strictEqual(canonicalConversationKey(flowOf([layer('eth', {}), layer('ipv4', {sip: '1.1.1.1', dip: '2.2.2.2'})])!), 'ip|1.1.1.1|2.2.2.2')
    assert.strictEqual(canonicalConversationKey(flowOf([layer('eth', {smac: 'aa', dmac: 'bb'})])!), 'eth|aa|bb')
    assert.strictEqual(flowOf([layer('raw', {}, false)]), null)
})

test('conversation key: topProtocol is the innermost protocol layer, skipping raw tails', (): void => {
    assert.strictEqual(topProtocolOf([layer('eth', {}), layer('ipv4', {}), layer('tcp', {}), layer('raw', {}, false)]), 'tcp')
    assert.strictEqual(topProtocolOf([layer('eth', {}), layer('arp', {})]), 'arp')
})

test('conversation key: hash32 is stable and non-negative 32-bit', (): void => {
    const h: number = hash32('tcp|10.0.0.1:1234|10.0.0.2:80')
    assert.strictEqual(h, hash32('tcp|10.0.0.1:1234|10.0.0.2:80'))
    assert.ok(h >= 0 && h <= 0xffffffff)
    assert.notStrictEqual(hash32('a'), hash32('b'))
})

test('frame indexer: add fills columns and both directions share a conversation hash', (): void => {
    const store: ColumnarIndexStore = new ColumnarIndexStore(8)
    const indexer: FrameIndexer = new FrameIndexer(store)
    const i0: number = indexer.add(tcpLayers('10.0.0.1', 1234, '10.0.0.2', 80), 100, 60, 60, 1.0)
    const i1: number = indexer.add(tcpLayers('10.0.0.2', 80, '10.0.0.1', 1234), 200, 66, 66, 1.5)
    assert.deepStrictEqual([i0, i1], [0, 1])
    const r0: FrameIndexRecord = store.get(0)!
    const r1: FrameIndexRecord = store.get(1)!
    assert.strictEqual(r0.fileOffset, 100)
    assert.strictEqual(r0.capturedLength, 60)
    assert.strictEqual(r0.timestamp, 1.0)
    assert.strictEqual(r0.conversationHash, r1.conversationHash, 'A→B and B→A land in one conversation')
    assert.strictEqual(indexer.conversationKey(r0.conversationHash), 'tcp|10.0.0.1:1234|10.0.0.2:80')
    assert.strictEqual(indexer.protocolName(r0.protocolId), 'tcp')
})

test('frame indexer: distinct protocols get distinct ids, unknown hash resolves to null', (): void => {
    const store: ColumnarIndexStore = new ColumnarIndexStore(8)
    const indexer: FrameIndexer = new FrameIndexer(store)
    indexer.add(tcpLayers('10.0.0.1', 1, '10.0.0.2', 2), 0, 10, 10, 0)
    indexer.add([layer('eth', {}), layer('arp', {})], 10, 28, 28, 1)
    assert.strictEqual(indexer.protocolName(store.get(0)!.protocolId), 'tcp')
    assert.strictEqual(indexer.protocolName(store.get(1)!.protocolId), 'arp')
    assert.notStrictEqual(store.get(0)!.protocolId, store.get(1)!.protocolId)
    assert.strictEqual(indexer.conversationKey(999999), null)
})
