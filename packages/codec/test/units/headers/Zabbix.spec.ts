import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

const MAGIC: string = '5a425844' // "ZBXD"
// {"request":"active checks","host":"Zabbix server"}
const CHECKS_BODY: string = '7b2272657175657374223a2261637469766520636865636b73222c22686f7374223a225a616262697820736572766572227d'

// Zabbix (tcp:10051) agent active-checks request — 13-byte header (ZBXD magic + flags + LE data length
// + LE reserved) + JSON body.
test('Zabbix active-checks: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('zabbix/active-checks').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'zabbix'])
    const zabbix: any = Layer(decoded, 'zabbix').data
    assert.strictEqual(zabbix.magic, MAGIC, 'ZBXD magic')
    assert.strictEqual(zabbix.flags, 1, 'flags 0x01 (uncompressed)')
    assert.strictEqual(zabbix.dataLength, 50, 'data length (little-endian) = body byte count')
    assert.strictEqual(zabbix.reserved, 0, 'reserved 0 (uncompressed)')
    assert.strictEqual(zabbix.body, CHECKS_BODY, 'JSON active-checks request body')
})

// Crafting: a minimal uncompressed message with an empty body and the Data Length auto-computed from the
// (empty) body — the minimal well-formed Zabbix message must re-encode byte-identically.
test('Zabbix faithfully encodes a crafted empty message and auto-computes the Data Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.2', dip: '192.0.2.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 60000, dstport: 10051}},
        {id: 'zabbix', data: {magic: MAGIC, flags: 1}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'zabbix'])
    const zabbix: any = Layer(decoded, 'zabbix').data
    assert.strictEqual(zabbix.flags, 1, 'uncompressed')
    assert.strictEqual(zabbix.dataLength, 0, 'auto-computed Data Length = 0 (empty body)')
    assert.strictEqual(zabbix.reserved, 0, 'reserved defaults to 0')
    assert.strictEqual(zabbix.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Data Length: a crafted message supplies an explicit (over-large) Data Length — it
// must be honored verbatim (not overwritten by the derived value), and the body stays bounded by the
// captured bytes so a lying length cannot read past the buffer. Round-trips byte-for-byte.
test('Zabbix honors an explicitly supplied Data Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 10051, dstport: 60000}},
        // body is 2 bytes ('{}') but Data Length claims 99 — honored, body bounded by captured bytes.
        {id: 'zabbix', data: {magic: MAGIC, flags: 1, dataLength: 99, reserved: 0, body: '7b7d'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const zabbix: any = Layer(decoded, 'zabbix').data
    assert.strictEqual(zabbix.dataLength, 99, 'supplied Data Length honored')
    assert.strictEqual(zabbix.body, '7b7d', 'body bounded by captured bytes despite the lying length')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Protocol-specific edge: the compressed flag (0x02) — Reserved carries the uncompressed size and the
// body is an opaque (zlib) blob. Both are kept verbatim and round-trip byte-for-byte.
test('Zabbix carries a compressed message: Reserved and the opaque body round-trip', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.2', dip: '192.0.2.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 60000, dstport: 10051}},
        {id: 'zabbix', data: {magic: MAGIC, flags: 2, reserved: 4096, body: '789c0102'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const zabbix: any = Layer(decoded, 'zabbix').data
    assert.strictEqual(zabbix.flags, 2, 'compressed flag')
    assert.strictEqual(zabbix.reserved, 4096, 'Reserved = uncompressed size (little-endian)')
    assert.strictEqual(zabbix.body, '789c0102', 'opaque compressed body kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/10051 payload whose Magic is not "ZBXD" must NOT be claimed as Zabbix (falls through
// to raw); and a truncated Zabbix message must survive decode without throwing.
test('Zabbix rejects a non-ZBXD magic on port 10051, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 10051}},
        // magic 0x00112233 (not "ZBXD") — no-signature bytes that do not collide with any content heuristic
        {id: 'raw', data: {data: '00112233' + '01' + '32000000' + '00000000' + '7b7d'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'zabbix'), 'non-ZBXD magic must not be claimed as Zabbix')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    // Truncate within the JSON body of the real fixture — decode must not throw.
    const full: Buffer = LoadPacket('zabbix/active-checks').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 8))
})
