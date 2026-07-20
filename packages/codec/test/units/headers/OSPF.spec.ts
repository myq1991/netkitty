import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// OSPFv2 Hello (RFC 2328) over IP protocol 89 — the 24-byte common header + the structured Hello body.
test('OSPFv2 Hello: common header + Hello body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ospf/hello').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'ospf'])
    const ospf: any = Layer(decoded, 'ospf').data
    assert.strictEqual(ospf.version, 2, 'OSPFv2')
    assert.strictEqual(ospf.type, 1, 'Hello')
    assert.strictEqual(ospf.routerId, '1.1.1.1')
    assert.strictEqual(ospf.areaId, '0.0.0.0')
    assert.strictEqual(ospf.auType, 0, 'null authentication')
    assert.strictEqual(ospf.hello.networkMask, '255.255.255.0')
    assert.strictEqual(ospf.hello.helloInterval, 10)
    assert.strictEqual(ospf.hello.routerDeadInterval, 40)
    assert.deepStrictEqual(ospf.hello.neighbors, ['2.2.2.2'])
})

// A non-Hello OSPF type (Database Description, type 2) keeps its body verbatim (rawBody) — the codec
// does not sub-decode the DD/LSR/LSU/LSAck bodies but round-trips them byte-for-byte.
test('OSPF non-Hello type keeps its body as rawBody (byte-perfect)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:05', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '224.0.0.5', protocol: 89, ttl: 1}},
        {id: 'ospf', data: {
            version: 2, type: 2, packetLength: 32, routerId: '1.1.1.1', areaId: '0.0.0.0',
            checksum: 0xf010, auType: 0, auth: '0000000000000000', rawBody: '05dc0207000003e8'
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'ospf'])
    const ospf: any = Layer(decoded, 'ospf').data
    assert.strictEqual(ospf.type, 2, 'Database Description')
    assert.strictEqual(ospf.rawBody, '05dc0207000003e8', 'DD body preserved verbatim')
    assert.ok(!ospf.hello || ospf.hello.networkMask === undefined, 'Hello body not decoded for a non-Hello type')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Crafting: a Hello with two neighbors — the neighbor list is bounded by the OSPF packet length.
test('OSPF faithfully encodes a crafted Hello with multiple neighbors', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:05', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '224.0.0.5', protocol: 89, ttl: 1}},
        {id: 'ospf', data: {
            version: 2, type: 1, packetLength: 52, routerId: '3.3.3.3', areaId: '0.0.0.1',
            checksum: 0x0000, auType: 0, auth: '0000000000000000',
            hello: {networkMask: '255.255.255.0', helloInterval: 10, options: 2, routerPriority: 1,
                routerDeadInterval: 40, designatedRouter: '192.168.1.1', backupDesignatedRouter: '0.0.0.0',
                neighbors: ['4.4.4.4', '5.5.5.5']}
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const ospf: any = Layer(decoded, 'ospf').data
    assert.strictEqual(ospf.routerId, '3.3.3.3')
    assert.deepStrictEqual(ospf.hello.neighbors, ['4.4.4.4', '5.5.5.5'])
    assert.strictEqual(ospf.hello.designatedRouter, '192.168.1.1')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A real OSPF Hello is 48 bytes and rides below the 60-byte minimum Ethernet frame, so on the wire it is
// padded. The neighbor list is bounded by the OSPF packet length, so the padding must route to a raw
// layer (not become bogus neighbors) and the whole frame must round-trip byte-for-byte.
test('OSPF Hello with trailing Ethernet padding: padding routes to raw, not bogus neighbors', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:05', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '224.0.0.5', protocol: 89, ttl: 1}},
        {id: 'ospf', data: {
            version: 2, type: 1, packetLength: 48, routerId: '1.1.1.1', areaId: '0.0.0.0',
            checksum: 0xf694, auType: 0, auth: '0000000000000000',
            hello: {networkMask: '255.255.255.0', helloInterval: 10, options: 2, routerPriority: 1,
                routerDeadInterval: 40, designatedRouter: '0.0.0.0', backupDesignatedRouter: '0.0.0.0',
                neighbors: ['2.2.2.2']}
        }},
        {id: 'raw', data: {data: 'aaaaaaaaaaaaaaaa'}} // 8 bytes of trailing L2 padding
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'ospf', 'raw'])
    const ospf: any = Layer(decoded, 'ospf').data
    assert.deepStrictEqual(ospf.hello.neighbors, ['2.2.2.2'], 'exactly one neighbor — padding not absorbed')
})

test('OSPF truncated mid-body: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('ospf/hello').buffer
    await AssertDecodeSurvives(full.subarray(0, 40))
})
