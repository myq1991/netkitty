import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// OpenFlow 1.3 (tcp:6653) Hello — 8-byte header (version + type + length + xid) + a version-bitmap body.
test('OpenFlow Hello: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('openflow/hello').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'openflow'])
    const of: any = Layer(decoded, 'openflow').data
    assert.strictEqual(of.version, 4, 'OF 1.3')
    assert.strictEqual(of.type, 0, 'Hello')
    assert.strictEqual(of.length, 16, 'total message length incl 8-byte header')
    assert.strictEqual(of.xid, 1, 'transaction id')
    assert.strictEqual(of.body, '0001000800000012', 'version-bitmap element (type 1, len 8, bitmap 0x12)')
})

// Crafting: a bodyless Echo Request (type 2) with the Length auto-computed from the (empty) body — the
// minimal well-formed OpenFlow message must re-encode byte-identically.
test('OpenFlow faithfully encodes a crafted Echo Request and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.2', dip: '192.0.2.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 6653}},
        {id: 'openflow', data: {version: 4, type: 2, xid: 99}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'openflow'])
    const of: any = Layer(decoded, 'openflow').data
    assert.strictEqual(of.type, 2, 'Echo Request')
    assert.strictEqual(of.length, 8, 'auto-computed Length = 8 (header only, empty body)')
    assert.strictEqual(of.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted Error (type 1) supplies an explicit Length — it must be honored
// verbatim (not overwritten by the derived value) so a message that carries any Length round-trips.
test('OpenFlow honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    // Error body: type 0 (OFPET_HELLO_FAILED), code 0 (OFPHFC_INCOMPATIBLE) => 4 bytes. Length = 8 + 4 = 12.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 6653, dstport: 40000}},
        {id: 'openflow', data: {version: 4, length: 12, type: 1, xid: 5, body: '00000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const of: any = Layer(decoded, 'openflow').data
    assert.strictEqual(of.type, 1, 'Error')
    assert.strictEqual(of.length, 12, 'supplied Length honored')
    assert.strictEqual(of.body, '00000000', 'HELLO_FAILED / INCOMPATIBLE')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/6653 payload shorter than the 8-byte header must NOT be claimed as OpenFlow (the
// port match requires the full header) and falls through to raw; and a truncated OpenFlow message must
// survive decode without throwing.
test('OpenFlow rejects a sub-header-length payload on port 6653, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 6653}},
        // 4 bytes of non-signature junk — below the 8-byte OpenFlow header
        {id: 'raw', data: {data: '99887766'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'openflow'), 'sub-header payload must not be claimed as OpenFlow')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('openflow/hello').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})

// honor a lying (too-short) Length: a crafted Echo Reply declares Length 3 (< the 8-byte header). Decode
// must not throw, the header still consumes its 8 bytes, and the value re-encodes verbatim (Length is a
// full-uint16-range honored field, so no Ajv rejection of the out-of-spec value).
test('OpenFlow survives a lying short Length and re-encodes it verbatim', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 6653}},
        {id: 'openflow', data: {version: 4, type: 3, length: 3, xid: 7, body: ''}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const of: any = Layer(decoded, 'openflow').data
    assert.strictEqual(of.type, 3, 'Echo Reply')
    assert.strictEqual(of.length, 3, 'lying short Length preserved')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Protocol-specific edge: two OpenFlow messages pipelined in one TCP segment. The first message is
// bounded by its Length, so its body does NOT swallow the trailing message; the trailing bytes fall
// through to raw (a leaf header advances only over its own message and does not re-match itself).
test('OpenFlow pipelining: the first message is bounded by its Length; the trailing message falls through to raw', async (): Promise<void> => {
    const first: string = '04000010000000010001000800000012'   // 16-byte Hello (version bitmap)
    const second: string = '0402000800000002'                   // 8-byte Echo Request
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 6653, dstport: 40000}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'openflow', 'raw'])
    const of: any = Layer(decoded, 'openflow').data
    assert.strictEqual(of.type, 0, 'first is Hello')
    assert.strictEqual(of.body, '0001000800000012', 'Hello body bounded by its Length — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing Echo Request left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
