import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// IAX2 (udp:4569) NEW message — a Full frame: 12-byte bit-packed header + Information-Element data.
test('IAX2 NEW: Full-frame header + data + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('iax2/new').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'iax2'])
    const iax2: any = Layer(decoded, 'iax2').data
    assert.strictEqual(iax2.fullFrame, true, 'F bit set => Full frame')
    assert.strictEqual(iax2.sourceCall, 1, 'source call number')
    assert.strictEqual(iax2.retransmit, 0, 'R bit clear')
    assert.strictEqual(iax2.destCall, 0, 'destination call number')
    assert.strictEqual(iax2.timestamp, 1, '32-bit full-frame timestamp')
    assert.strictEqual(iax2.oSeqno, 0, 'outbound seqno')
    assert.strictEqual(iax2.iSeqno, 0, 'inbound seqno')
    assert.strictEqual(iax2.frameType, 6, 'Frame Type 6 (IAX)')
    assert.strictEqual(iax2.subclassC, 0, 'C bit clear')
    assert.strictEqual(iax2.subclass, 1, 'Subclass 1 (NEW)')
    assert.strictEqual(iax2.data, '0b0200020104313233340605616c696365', 'IE data (VERSION, CALLEDNUM, USERNAME)')
})

// Crafting a Mini frame (F=0): 4-byte header (source call + 16-bit timestamp) + media payload. The
// minimal well-formed Mini frame must round-trip byte-identically and its decode must carry only the
// Mini fields (no destCall/seqno/subclass keys).
test('IAX2 crafts a Mini frame (F=0) and round-trips it byte-for-byte', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '66:77:88:99:aa:bb', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 4569, dstport: 4569}},
        {id: 'iax2', data: {fullFrame: false, sourceCall: 5, timestamp: 43981, data: 'deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'iax2'])
    const iax2: any = Layer(decoded, 'iax2').data
    assert.strictEqual(iax2.fullFrame, false, 'F bit clear => Mini frame')
    assert.strictEqual(iax2.sourceCall, 5, 'source call number')
    assert.strictEqual(iax2.timestamp, 43981, '16-bit truncated timestamp')
    assert.strictEqual(iax2.data, 'deadbeef', 'media payload')
    assert.strictEqual(iax2.destCall, undefined, 'no Full-frame fields on a Mini frame')
    assert.strictEqual(iax2.subclass, undefined, 'no Full-frame fields on a Mini frame')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Crafting a Full frame with the C bit set (subclass as power-of-two) and an explicit sub-header — the
// bit-packed fields must re-encode exactly (each writeBits preserves its neighbours).
test('IAX2 faithfully encodes a Full frame with the C bit set', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '66:77:88:99:aa:bb', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 4569, dstport: 4569}},
        {id: 'iax2', data: {fullFrame: true, sourceCall: 2, retransmit: 1, destCall: 3, timestamp: 4096, oSeqno: 7, iSeqno: 8, frameType: 2, subclassC: 1, subclass: 3, data: ''}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const iax2: any = Layer(decoded, 'iax2').data
    assert.strictEqual(iax2.retransmit, 1, 'R bit set')
    assert.strictEqual(iax2.destCall, 3, 'destination call preserved alongside R bit')
    assert.strictEqual(iax2.frameType, 2, 'Frame Type 2 (Voice)')
    assert.strictEqual(iax2.subclassC, 1, 'C bit set')
    assert.strictEqual(iax2.subclass, 3, 'subclass preserved alongside C bit')
    assert.strictEqual(iax2.data, '', 'empty data')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/4569 payload too short for the format its F bit announces must NOT be claimed as IAX2
// (a 6-byte F=1 payload needs the full 12-byte header) — it falls through to raw; and a truncated NEW
// message must survive decode without throwing.
test('IAX2 rejects a Full frame too short for its 12-byte header, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '66:77:88:99:aa:bb', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 4569, dstport: 4569}},
        // F=1 (0x80..) but only 6 bytes < the required 12-byte Full-frame header
        {id: 'raw', data: {data: '800100000102'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'iax2'), 'a Full frame short of 12 bytes must not be claimed as IAX2')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('iax2/new').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})
