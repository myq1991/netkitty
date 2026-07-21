import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// collectd binary network protocol (udp:25826): a flat sequence of parts — each part a 2-byte Type,
// a 2-byte Length (COUNTING the 4-byte header), and Length−4 value bytes.
test('collectd baseline: Host + Time + Values parts + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('collectd/baseline').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'collectd'])
    const collectd: any = Layer(decoded, 'collectd').data
    assert.strictEqual(collectd.parts.length, 3, 'Host + Time + Values')
    // Host (0x0000): length 14 = 4 header + "localhost\0" (10)
    assert.strictEqual(collectd.parts[0].type, 0x0000, 'Host')
    assert.strictEqual(collectd.parts[0].length, 14, 'Host length counts the 4-byte header')
    assert.strictEqual(collectd.parts[0].value, '6c6f63616c686f737400', '"localhost" + NUL')
    // Time (0x0001): length 12 = 4 header + 8-byte epoch
    assert.strictEqual(collectd.parts[1].type, 0x0001, 'Time')
    assert.strictEqual(collectd.parts[1].length, 12, 'Time length')
    assert.strictEqual(collectd.parts[1].value, '0000000063b0cdb1', '8-byte epoch')
    // Values (0x0006): length 15 = 4 header + count(2) + ds-type(1) + value(8)
    assert.strictEqual(collectd.parts[2].type, 0x0006, 'Values')
    assert.strictEqual(collectd.parts[2].length, 15, 'Values length')
    assert.strictEqual(collectd.parts[2].value, '0001010000000000004540', '1 gauge value = 42.0 (LE double)')
    assert.strictEqual(collectd.trailer, '', 'no trailing bytes')
})

// Crafting: parts supplied WITHOUT an explicit Length — each Length must be derived as 4 + value bytes,
// and the crafted datagram must re-decode/re-encode byte-identically.
test('collectd derives a part Length from the value when omitted', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 25826}},
        {id: 'collectd', data: {parts: [
            {type: 0x0000, value: '6c6f63616c686f737400'},  // Host "localhost\0" => len 14
            {type: 0x0001, value: '0000000063b0cdb1'}        // Time => len 12
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'collectd'])
    const collectd: any = Layer(decoded, 'collectd').data
    assert.strictEqual(collectd.parts[0].length, 14, 'derived Host Length = 4 + 10')
    assert.strictEqual(collectd.parts[1].length, 12, 'derived Time Length = 4 + 8')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: an explicit Length is written verbatim (not re-derived from the value byte count),
// so a crafted part can carry any Length. Inspect the encoded collectd payload directly (a lying Length
// desyncs the parser, so this asserts the encoder honors it rather than round-tripping through decode).
test('collectd honors an explicitly supplied part Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 25826}},
        // Type 0x0002 (Plugin), Length 0x0063 = 99 (a lie — the value is only 3 bytes)
        {id: 'collectd', data: {parts: [{type: 0x0002, length: 99, value: '6c6f63'}]}}
    ])
    // The collectd payload is the tail of the frame: Type(0002) Length(0063) Value(6c6f63).
    assert.ok(packet.toString('hex').endsWith('000200636c6f63'), 'supplied Length 99 honored verbatim')
})

// Negative: a truncated final part (its Length overruns the payload) must NOT be consumed as a part —
// its bytes are kept in `trailer` — and a malformed Length < 4 must not stall; both survive decode
// without throwing and re-encode byte-for-byte.
test('collectd keeps an overrunning/malformed final part as trailer, survives, re-encodes', async (): Promise<void> => {
    // One well-formed Host part, then a header claiming Length 0x00ff (255) with only 3 bytes present.
    const truncated: string = '0000000e6c6f63616c686f737400' + '000000ff6c6f63'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 25826}},
        {id: 'raw', data: {data: truncated}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'collectd'])
    const collectd: any = Layer(decoded, 'collectd').data
    assert.strictEqual(collectd.parts.length, 1, 'only the well-formed Host part consumed')
    assert.strictEqual(collectd.trailer, '000000ff6c6f63', 'overrunning part kept verbatim as trailer')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')

    // A Length < 4 cannot delimit its own header: the whole remainder becomes trailer (no stall).
    const badLen: string = '000000026c6f'
    const {packet: p2}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 25826}},
        {id: 'raw', data: {data: badLen}}
    ])
    const d2: CodecDecodeResult[] = await codec.decode(p2)
    const c2: any = Layer(d2, 'collectd').data
    assert.strictEqual(c2.parts.length, 0, 'Length < 4 not consumed as a part')
    assert.strictEqual(c2.trailer, badLen, 'malformed header kept verbatim')
    assert.strictEqual((await codec.encode(d2)).packet.toString('hex'), p2.toString('hex'), 'byte-perfect')

    // Truncated capture (drop trailing bytes) must survive decode without throwing.
    const full: Buffer = LoadPacket('collectd/baseline').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 5))
})
