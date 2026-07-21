import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// IPFIX / NetFlow v10 (udp:4739) — 16-byte Message Header + a Template Set (id 2) and a Data Set (id 256).
test('IPFIX: header + template/data sets + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ipfix/template-data').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ipfix'])
    const ipfix: any = Layer(decoded, 'ipfix').data
    assert.strictEqual(ipfix.version, 10, 'IPFIX version is always 10')
    assert.strictEqual(ipfix.length, 44, 'total message length incl 16-byte header')
    assert.strictEqual(ipfix.exportTime, 1546499135, 'export time (seconds since epoch)')
    assert.strictEqual(ipfix.sequenceNumber, 0, 'sequence number')
    assert.strictEqual(ipfix.observationDomainId, 256, 'observation domain id')
    assert.strictEqual(ipfix.sets.length, 2, 'two sets: template + data')
    assert.strictEqual(ipfix.sets[0].setId, 2, 'first set is a Template Set (id 2)')
    assert.strictEqual(ipfix.sets[0].setLength, 16, 'template set length')
    assert.strictEqual(ipfix.sets[0].body, '0100000200080004000c0004', 'template 256: srcIPv4(8,4) dstIPv4(12,4)')
    assert.strictEqual(ipfix.sets[1].setId, 256, 'second set is a Data Set keyed by Template 256')
    assert.strictEqual(ipfix.sets[1].setLength, 12, 'data set length')
    assert.strictEqual(ipfix.sets[1].body, 'c0000201c0000202', 'flow record 192.0.2.1 -> 192.0.2.2')
})

// Crafting: a single Data Set message with both the message Length and the Set Length auto-computed
// (neither supplied) — the minimal well-formed IPFIX message must re-encode byte-identically.
test('IPFIX faithfully encodes a crafted message and auto-computes the Length and Set Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 45678, dstport: 4739}},
        {id: 'ipfix', data: {version: 10, observationDomainId: 7, sets: [{setId: 256, body: 'c0000201c0000202'}]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ipfix'])
    const ipfix: any = Layer(decoded, 'ipfix').data
    assert.strictEqual(ipfix.version, 10)
    assert.strictEqual(ipfix.length, 28, 'auto-computed Length = 16 header + 12 set')
    assert.strictEqual(ipfix.sets[0].setLength, 12, 'auto-computed Set Length = 4 header + 8 body')
    assert.strictEqual(ipfix.sets[0].body, 'c0000201c0000202')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted message supplies an explicit (deliberately wrong) message Length —
// it must be honored verbatim (not overwritten by the derived value) so a lying message round-trips.
test('IPFIX honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 45678, dstport: 4739}},
        {id: 'ipfix', data: {version: 10, length: 999, observationDomainId: 7, sets: [{setId: 256, setLength: 12, body: 'c0000201c0000202'}]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const ipfix: any = Layer(decoded, 'ipfix').data
    assert.strictEqual(ipfix.length, 999, 'supplied Length honored (not derived over)')
    assert.strictEqual(ipfix.sets[0].body, 'c0000201c0000202', 'sets bounded by captured bytes despite the lying Length')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/4739 payload whose Version is not 10 must NOT be claimed as IPFIX (falls through to
// raw); and a truncated IPFIX message must survive decode without throwing.
test('IPFIX rejects a non-10 Version on port 4739, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 45678, dstport: 4739}},
        // Version 0x0009 (NetFlow v9), not IPFIX — must not be claimed by this codec
        {id: 'raw', data: {data: '0009002c5c2db43f00000000000000070002001001000002'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'ipfix'), 'non-10 Version must not be claimed as IPFIX')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('ipfix/template-data').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})

// Protocol-specific edge: the Sets walk is bounded by the message Length, so trailing bytes after the
// message (padding / a pipelined message) are NOT swallowed into the last Set — they fall through to
// raw. Both directions round-trip byte-for-byte.
test('IPFIX: the Sets are bounded by the message Length; trailing bytes fall through to raw', async (): Promise<void> => {
    const message: string = '000a001c000000010000000000000007' + '0100000cc0000201c0000202' // 28-byte msg, length 0x1c
    const trailing: string = 'deadbeef'                                                       // extra bytes after the message
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 45678, dstport: 4739}},
        {id: 'raw', data: {data: message + trailing}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ipfix', 'raw'])
    const ipfix: any = Layer(decoded, 'ipfix').data
    assert.strictEqual(ipfix.length, 28, 'message length 0x1c')
    assert.strictEqual(ipfix.sets.length, 1, 'one Data Set only — trailing bytes not absorbed')
    assert.strictEqual(ipfix.sets[0].body, 'c0000201c0000202', 'Data Set bounded by its Set Length')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, trailing, 'trailing bytes left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
