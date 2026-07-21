import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

const MAGIC: string = '000117e8'

// CODESYS V3 (tcp:2455) block-driver frame — 8-byte header (magic + little-endian length) + payload.
test('CODESYS block driver: header + payload + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('codesys/block-driver').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'codesys'])
    const codesys: any = Layer(decoded, 'codesys').data
    assert.strictEqual(codesys.magic, MAGIC, 'block-driver magic')
    assert.strictEqual(codesys.length, 20, 'little-endian payload byte count')
    assert.strictEqual(codesys.payload, 'c50000400043d158ac105981ac10598200008383', 'verbatim L3 datagram payload')
})

// Crafting: build a frame with the Length auto-computed from the payload — confirm the little-endian
// Length lands correctly and the frame round-trips byte-for-byte.
test('CODESYS faithfully encodes a crafted frame and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 2455}},
        {id: 'codesys', data: {magic: MAGIC, payload: 'c500004000430102030405060102030405060708'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'codesys'])
    const codesys: any = Layer(decoded, 'codesys').data
    assert.strictEqual(codesys.magic, MAGIC)
    assert.strictEqual(codesys.length, 20, 'auto-computed Length = payload byte count')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted frame supplies an explicit Length — it must be honored verbatim
// (not overwritten by the derived value) so a frame that carries any Length round-trips.
test('CODESYS honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.2', dip: '10.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 2455, dstport: 40000}},
        // Length 0 (empty payload lie) is honored: 00 00 00 00 written, no payload consumed.
        {id: 'codesys', data: {magic: MAGIC, length: 0, payload: ''}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const codesys: any = Layer(decoded, 'codesys').data
    assert.strictEqual(codesys.length, 0, 'supplied Length honored')
    assert.strictEqual(codesys.payload, '', 'empty payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/2455 payload that does not begin with the block-driver magic must NOT be claimed as
// CODESYS (falls through to raw); and a truncated frame must survive decode without throwing.
test('CODESYS rejects a non-magic payload on port 2455, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 2455}},
        // No CODESYS signature — arbitrary non-magic bytes that collide with no registered heuristic.
        {id: 'raw', data: {data: 'abababababababababababab'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'codesys'), 'non-magic payload must not be claimed as CODESYS')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('codesys/block-driver').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})

// Protocol-specific edge: two block-driver frames pipelined in one TCP segment. The first frame is
// bounded by its Length so its payload does NOT swallow the trailing frame; the trailing bytes fall
// through to raw (a leaf header advances only over its own frame and produces no further demux key,
// matching the length-bounded-TCP-payload precedent). Both directions round-trip byte-for-byte.
test('CODESYS pipelining: the first frame is bounded by its Length; the trailing frame falls through to raw', async (): Promise<void> => {
    const firstPayload: string = 'c50000400043d158ac105981ac10598200008383'   // 20 bytes
    const secondPayload: string = 'c5000001003411223344556677889900aabbccdd'  // 20 bytes
    const first: string = MAGIC + '14000000' + firstPayload                    // 28-byte frame
    const second: string = MAGIC + '14000000' + secondPayload                  // 28-byte frame
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 2455}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'codesys', 'raw'])
    const codesys: any = Layer(decoded, 'codesys').data
    assert.strictEqual(codesys.payload, firstPayload, 'payload bounded by its Length — trailing frame not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing frame left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
