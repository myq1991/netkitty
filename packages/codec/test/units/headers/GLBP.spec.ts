import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// The Hello TLV value (Length − 2 = 26 bytes): priority 100, helloint 3000, holdint 10000, virtual IPv4 192.0.1.1.
const HELLO_VALUE: string = '00140064000000000bb8000027100258384000000104c0000101'

// GLBP (udp:3222) Hello — 12-byte header (version/unknown1/group/unknown2/ownerId) + one Hello TLV.
test('GLBP Hello: header + Hello TLV + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('glbp/hello').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'glbp'])
    const glbp: any = Layer(decoded, 'glbp').data
    assert.strictEqual(glbp.version, 1, 'Version (Wireshark heuristic requires 1)')
    assert.strictEqual(glbp.unknown1, 0, 'Unknown1')
    assert.strictEqual(glbp.group, 1, 'GLBP group number')
    assert.strictEqual(glbp.unknown2, '0000', 'Unknown2 kept verbatim')
    assert.strictEqual(glbp.ownerId, '0007b400a001', 'Owner ID (MAC) kept verbatim as hex')
    assert.strictEqual(glbp.tlvs.length, 1, 'one TLV')
    assert.strictEqual(glbp.tlvs[0].type, 1, 'Hello TLV')
    assert.strictEqual(glbp.tlvs[0].length, 28, 'on-wire Length = whole TLV size incl 2-byte header')
    assert.strictEqual(glbp.tlvs[0].value, HELLO_VALUE, 'Hello value kept verbatim')
    assert.strictEqual(glbp.trailing, '', 'no trailing bytes')
})

// Crafting: a GLBP message with one TLV whose Length is auto-derived from the (2-byte) value — the whole
// TLV size = 2-byte header + value bytes. The crafted message must re-encode byte-identically.
test('GLBP faithfully encodes a crafted message and auto-derives the TLV Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:66', smac: '00:07:b4:00:a0:01', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '224.0.0.102', protocol: 17}},
        {id: 'udp', data: {srcport: 3222, dstport: 3222}},
        {id: 'glbp', data: {version: 1, unknown1: 0, group: 5, unknown2: '0000', ownerId: '00c0ffee0001', tlvs: [{type: 1, value: '0011'}]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'glbp'])
    const glbp: any = Layer(decoded, 'glbp').data
    assert.strictEqual(glbp.group, 5, 'group')
    assert.strictEqual(glbp.tlvs[0].length, 4, 'auto-derived Length = 2 header + 2 value bytes')
    assert.strictEqual(glbp.tlvs[0].value, '0011', 'value')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length + trailing preservation: an explicit TLV Length is honored (not overwritten by
// the derived value), and bytes after the last TLV survive verbatim in `trailing`. Both round-trip exactly.
test('GLBP honors an explicit TLV Length and preserves trailing bytes', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:66', smac: '00:07:b4:00:a0:01', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '224.0.0.102', protocol: 17}},
        {id: 'udp', data: {srcport: 3222, dstport: 3222}},
        {id: 'glbp', data: {version: 1, unknown1: 2, group: 9, unknown2: 'abcd', ownerId: '001122334455', tlvs: [{type: 2, length: 5, value: '010203'}], trailing: 'dead'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const glbp: any = Layer(decoded, 'glbp').data
    assert.strictEqual(glbp.unknown1, 2, 'Unknown1')
    assert.strictEqual(glbp.tlvs[0].type, 2, 'Request/Response TLV')
    assert.strictEqual(glbp.tlvs[0].length, 5, 'supplied Length honored (5 = 2 header + 3 value)')
    assert.strictEqual(glbp.tlvs[0].value, '010203', 'value')
    assert.strictEqual(glbp.trailing, 'dead', 'trailing bytes preserved verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/3222 datagram whose payload is shorter than the 12-byte fixed header must NOT be claimed
// as GLBP (falls through to raw); and a truncated GLBP message must survive decode without throwing.
test('GLBP rejects a sub-header datagram on port 3222, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:66', smac: '00:07:b4:00:a0:01', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '224.0.0.102', protocol: 17}},
        {id: 'udp', data: {srcport: 3222, dstport: 3222}},
        // 8 payload bytes — below the 12-byte fixed header, so not a GLBP message
        {id: 'raw', data: {data: '0100000100000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'glbp'), 'sub-header datagram must not be claimed as GLBP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('glbp/hello').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 5))
})
