import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// PTPv2 (IEEE 1588-2008) Sync over raw Ethernet, EtherType 0x88f7 — 34-byte common header + 10-byte body.
test('PTP L2 Sync: common header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ptp/sync-l2').buffer)
    AssertLayers(decoded, ['eth', 'ptp'])
    const ptp: any = Layer(decoded, 'ptp').data
    assert.strictEqual(ptp.messageType, 0, 'Sync')
    assert.strictEqual(ptp.versionPTP, 2, 'PTPv2')
    assert.strictEqual(ptp.messageLength, 44, 'total message length incl 34-byte header')
    assert.strictEqual(ptp.domainNumber, 0, 'domain 0')
    assert.strictEqual(ptp.flags, '0200', 'twoStep flag')
    assert.strictEqual(ptp.correctionField, '0000000000000000', 'zero correction')
    assert.strictEqual(ptp.sourcePortIdentity.clockIdentity, '001b19fffe000000', 'clock identity')
    assert.strictEqual(ptp.sourcePortIdentity.portNumber, 1, 'source port number')
    assert.strictEqual(ptp.controlField, 0, 'Sync control field')
    assert.strictEqual(ptp.body, '00000000000000000000', '10-byte origin timestamp')
})

// PTPv2 Sync over UDP/IPv4 event port 319 — same message, dispatched via the udpport demux instead.
test('PTP UDP:319 Sync: header + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ptp/sync-udp319').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ptp'])
    const ptp: any = Layer(decoded, 'ptp').data
    assert.strictEqual(ptp.messageType, 0, 'Sync')
    assert.strictEqual(ptp.messageLength, 44, 'message length')
    assert.strictEqual(ptp.sourcePortIdentity.portNumber, 1, 'source port number')
})

// Crafting: a Delay_Req (messageType 1, empty body) with the messageLength auto-derived from the (empty)
// body — the minimal 34-byte PTP message must re-encode byte-identically.
test('PTP faithfully encodes a crafted Delay_Req and auto-derives messageLength', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:1b:19:00:00:00', smac: '00:00:00:00:00:00', etherType: '88f7'}},
        {id: 'ptp', data: {messageType: 1, versionPTP: 2, controlField: 1}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ptp'])
    const ptp: any = Layer(decoded, 'ptp').data
    assert.strictEqual(ptp.messageType, 1, 'Delay_Req')
    assert.strictEqual(ptp.messageLength, 34, 'auto-derived messageLength = 34 (header only, empty body)')
    assert.strictEqual(ptp.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive messageLength: a crafted Announce supplies an explicit messageLength — it must be
// honored verbatim (not overwritten by the derived value) so a message carrying any length round-trips.
test('PTP honors an explicitly supplied messageLength (does not derive over it)', async (): Promise<void> => {
    // Announce (messageType 0xB) with a 20-byte body => messageLength 54.
    const body: string = 'a1'.repeat(20)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:1b:19:00:00:00', smac: '00:00:00:00:00:00', etherType: '88f7'}},
        {id: 'ptp', data: {messageType: 0xb, versionPTP: 2, messageLength: 54, controlField: 5, body: body}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const ptp: any = Layer(decoded, 'ptp').data
    assert.strictEqual(ptp.messageType, 0xb, 'Announce')
    assert.strictEqual(ptp.messageLength, 54, 'supplied messageLength honored')
    assert.strictEqual(ptp.body, body, '20-byte body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/319 payload too short for the 34-byte common header must NOT be claimed as PTP (falls
// through to raw); and a truncated PTP message must survive decode without throwing.
test('PTP rejects a sub-header UDP:319 payload, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '224.0.1.129', protocol: 17}},
        {id: 'udp', data: {srcport: 319, dstport: 319}},
        // only 4 bytes of payload — far below the 34-byte common header
        {id: 'raw', data: {data: '00022222'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'ptp'), 'sub-header payload must not be claimed as PTP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('ptp/sync-l2').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})
