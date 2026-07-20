import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// BACnet/IP (udp:47808) Who-Is broadcast — the BVLC header + verbatim NPDU/APDU payload.
test('BACnet/IP Who-Is: BVLC header + NPDU/APDU payload + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('bacnet/who-is').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'bacnet'])
    const bacnet: any = Layer(decoded, 'bacnet').data
    assert.strictEqual(bacnet.type, '81', 'BVLC type BACnet/IP')
    assert.strictEqual(bacnet.function, 0x0b, 'Original-Broadcast-NPDU')
    assert.strictEqual(bacnet.length, 12, 'whole-message length')
    assert.strictEqual(bacnet.payload, '0120ffff00ff1008', 'NPDU + APDU kept verbatim')
})

// Crafting: an Original-Unicast-NPDU (function 0x0A) with the Length auto-computed from the payload.
test('BACnet faithfully encodes a crafted Unicast-NPDU and auto-computes the BVLC Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 47808, dstport: 47808}},
        {id: 'bacnet', data: {type: '81', function: 0x0a, payload: '0100100a'}} // version 1, ctl 0, APDU
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'bacnet'])
    const bacnet: any = Layer(decoded, 'bacnet').data
    assert.strictEqual(bacnet.function, 0x0a, 'Original-Unicast-NPDU')
    // Length = 4-byte header + 4-byte payload = 8
    assert.strictEqual(bacnet.length, 8, 'auto-computed BVLC Length')
    assert.strictEqual(bacnet.payload, '0100100a')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A UDP/47808 payload without the 0x81 BVLC type must fall through to raw.
test('BACnet rejects a payload without the 0x81 BVLC type (falls through to raw)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 47808}},
        {id: 'raw', data: {data: '82ff000401'}} // type 0x82, not 0x81
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'bacnet'), 'must not claim a non-BACnet payload')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
})

test('BACnet truncated mid-message: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('bacnet/who-is').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 3))
})
