import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

const SLOW_MAC: string = '01:80:c2:00:00:02'
const RESERVED_90: string = '00'.repeat(90)

// Marker Protocol (Slow Protocols, ethertype 0x8809, subtype 2) — a Marker Information PDU carried
// directly in an Ethernet II frame. TLVs: Marker Information (type 1, len 0x10) + Terminator (type 0).
test('Marker Information: subtype/version + TLVs + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('marker/information').buffer)
    AssertLayers(decoded, ['eth', 'marker'])
    const marker: any = Layer(decoded, 'marker').data
    assert.strictEqual(marker.subtype, 2, 'subtype 2 = Marker')
    assert.strictEqual(marker.version, 1, 'version 1')
    assert.strictEqual(marker.tlvs.length, 2, 'Marker Information TLV + Terminator')
    assert.strictEqual(marker.tlvs[0].type, 1, 'Marker Information TLV')
    assert.strictEqual(marker.tlvs[0].length, 16, 'on-wire length 0x10 (incl 2 header octets)')
    // value = Requester_Port(0001) + Requester_System(001122334455) + Requester_Transaction_ID(0000002a) + Pad(0000)
    assert.strictEqual(marker.tlvs[0].value, '00010011223344550000002a0000', 'requester port/system/txid/pad')
    assert.strictEqual(marker.tlvs[1].type, 0, 'Terminator')
    assert.strictEqual(marker.tlvs[1].length, 0, 'Terminator length 0')
    assert.strictEqual(marker.reserved, RESERVED_90, '90 reserved octets after the Terminator')
})

// A Marker Response PDU (TLV type 2) must decode and round-trip byte-for-byte just the same.
test('Marker Response: TLV type 2 round-trips byte-for-byte', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('marker/response').buffer)
    AssertLayers(decoded, ['eth', 'marker'])
    const marker: any = Layer(decoded, 'marker').data
    assert.strictEqual(marker.subtype, 2, 'subtype 2 = Marker')
    assert.strictEqual(marker.tlvs[0].type, 2, 'Marker Response TLV')
    assert.strictEqual(marker.tlvs[0].value, '0002aabbccddeeff0000007b0000', 'requester port/system/txid/pad')
})

// Crafting: a Marker Information PDU whose TLV length is auto-derived from the value (14 value bytes +
// the 2 header octets = 0x10). The crafted frame must re-encode byte-identically.
test('Marker faithfully encodes a crafted PDU and auto-derives the TLV length', async (): Promise<void> => {
    const infoValue: string = '0001001122334455000000010000'   // port 1, system 00:11:..:55, txid 1, pad
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: SLOW_MAC, smac: '00:11:22:33:44:55', etherType: '8809'}},
        {id: 'marker', data: {subtype: 2, version: 1, tlvs: [{type: 1, value: infoValue}, {type: 0}], reserved: RESERVED_90}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'marker'])
    const marker: any = Layer(decoded, 'marker').data
    assert.strictEqual(marker.tlvs[0].length, 16, 'length auto-derived = 14 value + 2 header octets')
    assert.strictEqual(marker.tlvs[1].type, 0, 'Terminator')
    assert.strictEqual(marker.tlvs[1].length, 0, 'Terminator length auto-derived to 0')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted TLV supplies an explicit (lying) Length — it must be honored verbatim,
// not overwritten by the derived value, so a crafted PDU round-trips.
test('Marker honors an explicitly supplied TLV Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: SLOW_MAC, smac: '00:11:22:33:44:55', etherType: '8809'}},
        {id: 'marker', data: {subtype: 2, version: 1, tlvs: [{type: 1, length: 16, value: '0001001122334455000000010000'}, {type: 0, length: 0}], reserved: RESERVED_90}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const marker: any = Layer(decoded, 'marker').data
    assert.strictEqual(marker.tlvs[0].length, 16, 'supplied length honored')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a Slow-Protocols frame whose subtype is neither 1 (LACP) nor 2 (Marker) must NOT be claimed
// as Marker (falls through to raw); and a truncated Marker PDU must survive decode without throwing.
test('Marker rejects a non-2 subtype, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: SLOW_MAC, smac: '00:11:22:33:44:55', etherType: '8809'}},
        // subtype 3 (some other Slow Protocol) — not Marker
        {id: 'raw', data: {data: '0301' + '01100001001122334455000000010000' + '0000' + RESERVED_90}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'marker'), 'subtype 3 must not be claimed as Marker')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('marker/information').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 40))
})
