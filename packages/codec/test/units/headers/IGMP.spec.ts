import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// IGMPv2 Membership Report (ip proto 2, Type 0x16) — fixed 4-byte header + 4-byte group address.
test('IGMPv2 Report: header + group address + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('igmp/v2-report').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'igmp'])
    const igmp: any = Layer(decoded, 'igmp').data
    assert.strictEqual(igmp.type, 0x16, 'Membership Report v2')
    assert.strictEqual(igmp.maxRespCode, 0, 'Max Resp Code unused in a report')
    assert.strictEqual(igmp.checksum, 0x08fd, 'checksum honored verbatim')
    assert.strictEqual(igmp.groupAddress, '224.1.1.1', 'reported multicast group')
})

// IGMPv2 General Query (ip proto 2, Type 0x11, total length 8) — group 0.0.0.0, Max Resp Code 100.
test('IGMPv2 General Query: header + group address + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('igmp/v2-query').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'igmp'])
    const igmp: any = Layer(decoded, 'igmp').data
    assert.strictEqual(igmp.type, 0x11, 'Membership Query')
    assert.strictEqual(igmp.maxRespCode, 100, 'Max Resp Code 100 (10s)')
    assert.strictEqual(igmp.groupAddress, '0.0.0.0', 'general query targets all groups')
})

// IGMPv3 Membership Query (Type 0x11 with a >=12-byte payload): the extra v3 fields (Resv/S/QRV, QQIC,
// Number of Sources, source list) are parsed. Number of Sources is omitted here and honor-else-derived
// from the two source addresses. An explicit ipv4 length makes the v3 body reachable at encode time
// (the derived length is only filled in a post-packet handler, after IGMP encodes).
test('IGMPv3 Query: v3 source fields + honor-else-derive Number of Sources + byte-perfect', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:01', smac: '00:11:22:33:44:66', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '224.0.0.1', protocol: 2, length: 40, ttl: 1}},
        {id: 'igmp', data: {type: 0x11, maxRespCode: 0x64, checksum: 0, groupAddress: '0.0.0.0', resvSQRV: 0x02, qqic: 0x7d, sources: '0a0000010a000002'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'igmp'])
    const igmp: any = Layer(decoded, 'igmp').data
    assert.strictEqual(igmp.type, 0x11, 'v3 Query')
    assert.strictEqual(igmp.resvSQRV, 0x02, 'Resv/S/QRV')
    assert.strictEqual(igmp.qqic, 0x7d, 'QQIC')
    assert.strictEqual(igmp.numSources, 2, 'Number of Sources derived from the two source addresses')
    assert.strictEqual(igmp.sources, '0a0000010a000002', '10.0.0.1 and 10.0.0.2 kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// IGMPv3 Membership Report (Type 0x22): bytes 4-7 are reserved + Number of Group Records (no group
// address), then the group records kept as bounded hex.
test('IGMPv3 Report: reserved + group-record count + bounded records hex + byte-perfect', async (): Promise<void> => {
    // one 12-byte group record: record type 0x04 (CHANGE_TO_EXCLUDE), aux len 0, 0 sources, group 224.0.0.22
    const records: string = '0400' + '0000' + 'e0000016'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:16', smac: '00:11:22:33:44:77', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.20', dip: '224.0.0.22', protocol: 2, length: 36, ttl: 1}},
        {id: 'igmp', data: {type: 0x22, maxRespCode: 0, checksum: 0, reserved: '0000', numGroupRecords: 1, records: records}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'igmp'])
    const igmp: any = Layer(decoded, 'igmp').data
    assert.strictEqual(igmp.type, 0x22, 'v3 Report')
    assert.strictEqual(igmp.numGroupRecords, 1, 'one group record')
    assert.strictEqual(igmp.groupAddress, undefined, 'v3 Report has no top-level group address')
    assert.strictEqual(igmp.records, records, 'group record kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: an ip-proto-2 payload shorter than the 8-byte minimum must NOT be claimed as IGMP (falls
// through to raw); a garbage 8-byte payload survives decode and re-encodes faithfully; and a truncated
// well-formed report survives decode without throwing.
test('IGMP min-length guard, garbage survival, and truncation survival', async (): Promise<void> => {
    // 4-byte proto-2 payload — below the 8-byte guard, so IGMP must not claim it.
    const short: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:01', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '224.0.0.1', protocol: 2}},
        {id: 'raw', data: {data: '11640000'}}
    ])
    const shortDecoded: CodecDecodeResult[] = await codec.decode(short.packet)
    assert.ok(!shortDecoded.some((l: CodecDecodeResult): boolean => l.id === 'igmp'), 'a sub-8-byte proto-2 payload must not be claimed as IGMP')
    assert.strictEqual(shortDecoded[shortDecoded.length - 1].id, 'raw')

    // Garbage 8-byte payload on proto 2 — decodes as IGMP best-effort and re-encodes faithfully.
    const garbage: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:01', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '224.0.0.1', protocol: 2}},
        {id: 'raw', data: {data: 'ff00abcd11223344'}}
    ])
    const garbageDecoded: CodecDecodeResult[] = await AssertDecodeSurvives(garbage.packet)
    assert.ok(garbageDecoded.some((l: CodecDecodeResult): boolean => l.id === 'igmp'), 'garbage on proto 2 decodes as IGMP')
    assert.strictEqual((await codec.encode(garbageDecoded)).packet.toString('hex'), garbage.packet.toString('hex'), 'faithful re-encode of garbage')

    // Truncated well-formed report (last 4 bytes of the group address dropped) survives decode.
    const full: Buffer = LoadPacket('igmp/v2-report').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})
