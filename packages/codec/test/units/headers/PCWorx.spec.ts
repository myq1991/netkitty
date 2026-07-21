import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// PCWorx (tcp:1962) initial handshake request — the real Redpoint pcworx-info.nse probe packet:
// 4-byte header (opcode 0x01, service 0x01, length 0x001a=26 = whole message incl header) + 22-byte body.
test('PCWorx handshake: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('pcworx/handshake-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pcworx'])
    const pcworx: any = Layer(decoded, 'pcworx').data
    assert.strictEqual(pcworx.opcode, 1, 'opcode 0x01')
    assert.strictEqual(pcworx.service, 1, 'service 0x01 (request)')
    assert.strictEqual(pcworx.length, 26, 'total message length incl 4-byte header')
    assert.strictEqual(pcworx.body, '0000000078800003000c494245544830314e305f4d00', '22-byte handshake body')
})

// Crafting + honor-else-derive: a request with the Length OMITTED must auto-compute Length = 4 (header)
// + body length, and re-encode byte-identically.
test('PCWorx faithfully encodes a crafted request and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.10', dip: '192.168.0.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 1962}},
        {id: 'pcworx', data: {opcode: 1, service: 6, body: '00020000000000ff0400'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pcworx'])
    const pcworx: any = Layer(decoded, 'pcworx').data
    assert.strictEqual(pcworx.service, 6, 'service 6')
    assert.strictEqual(pcworx.length, 14, 'auto-computed Length = 4 header + 10 body')
    assert.strictEqual(pcworx.body, '00020000000000ff0400', 'body preserved')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted response supplies an explicit Length — it must be honored verbatim
// (not overwritten by the derived value) so a message that carries any Length round-trips.
test('PCWorx honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    // response: service 0x81 (high bit set), explicit length 14, 10-byte body
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.20', dip: '192.168.0.10', protocol: 6}},
        {id: 'tcp', data: {srcport: 1962, dstport: 51000}},
        {id: 'pcworx', data: {opcode: 1, service: 0x81, length: 14, body: '00020000000000ff0400'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const pcworx: any = Layer(decoded, 'pcworx').data
    assert.strictEqual(pcworx.service, 0x81, 'response service bit')
    assert.strictEqual(pcworx.length, 14, 'supplied Length honored')
    assert.strictEqual(pcworx.body, '00020000000000ff0400', 'body preserved')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a too-short TCP/1962 payload (< 4-byte header) must NOT be claimed as PCWorx (falls through
// to raw); and a truncated PCWorx message must survive decode without throwing.
test('PCWorx rejects a too-short payload on port 1962, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.10', dip: '192.168.0.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 1962}},
        // only 3 bytes of payload — shorter than the 4-byte PCWorx header
        {id: 'raw', data: {data: '010100'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'pcworx'), 'a sub-header payload must not be claimed as PCWorx')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('pcworx/handshake-request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})

// Protocol-specific edge: two PCWorx messages pipelined in one TCP segment. The first message is bounded
// by its Length, so its body does NOT swallow the trailing message; the trailing bytes fall through to
// raw (a leaf header advances only over its own message and does not re-match itself, matching the
// length-bounded-TCP-payload precedent). Both directions round-trip byte-for-byte.
test('PCWorx pipelining: the first message is bounded by its Length; the trailing message falls through to raw', async (): Promise<void> => {
    const first: string = '0106000e00020000000000ff0400'   // length 0x000e=14 => whole 14-byte message
    const second: string = '01010009aabbccdd00'            // length 0x0009=9  => whole 9-byte message
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.20', dip: '192.168.0.10', protocol: 6}},
        {id: 'tcp', data: {srcport: 1962, dstport: 51000}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pcworx', 'raw'])
    const pcworx: any = Layer(decoded, 'pcworx').data
    assert.strictEqual(pcworx.length, 14, 'first message length')
    assert.strictEqual(pcworx.body, '00020000000000ff0400', 'first body bounded by its Length — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing message left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
