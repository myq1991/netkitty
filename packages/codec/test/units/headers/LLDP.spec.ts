import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Minimal LLDPDU over Ethernet II (EtherType 0x88CC): the three mandatory TLVs (Chassis ID, Port ID,
// TTL) + End Of LLDPDU, padded to the 60-byte Ethernet minimum. Byte-perfect round-trip.
test('LLDP basic: mandatory TLV decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('lldp/basic').buffer)
    AssertLayers(decoded, ['eth', 'lldp'])
    const lldp: any = Layer(decoded, 'lldp').data
    // Chassis ID(1), Port ID(2), Time To Live(3), End Of LLDPDU(0).
    assert.deepStrictEqual(lldp.tlvs.map((t: any): number => t.type), [1, 2, 3, 0])
    assert.strictEqual(lldp.tlvs[0].value, '04001122334455', 'Chassis ID subtype 4 (MAC) + MAC')
    assert.strictEqual(lldp.tlvs[1].value, '03001122334455', 'Port ID subtype 3 (MAC) + MAC')
    assert.strictEqual(lldp.tlvs[2].value, '0078', 'TTL = 120s')
    assert.deepStrictEqual(lldp.tlvs[3], {type: 0, value: ''}, 'End Of LLDPDU preserved as an empty TLV')
    assert.strictEqual(lldp.padding, '00'.repeat(22), 'Ethernet padding after the End TLV kept verbatim')
})

// Craft an LLDPDU from scratch (no padding) and require a byte-perfect encode→decode→encode round-trip.
test('LLDP crafted LLDPDU: encode → decode → re-encode is byte-identical', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:0e', smac: 'aa:bb:cc:dd:ee:ff', etherType: '88cc'}},
        {id: 'lldp', data: {tlvs: [
            {type: 1, value: '04aabbccddeeff'},
            {type: 2, value: '0501'},
            {type: 3, value: '003c'},
            {type: 0, value: ''}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'lldp'])
    const lldp: any = Layer(decoded, 'lldp').data
    assert.deepStrictEqual(lldp.tlvs, [
        {type: 1, value: '04aabbccddeeff'},
        {type: 2, value: '0501'},
        {type: 3, value: '003c'},
        {type: 0, value: ''}
    ])
    assert.strictEqual(lldp.padding, '', 'no trailing bytes → no padding')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// An optional TLV after TTL (e.g. System Name, type 5) followed by the End TLV, then trailing padding —
// everything must round-trip, including the bytes after the End Of LLDPDU marker.
test('LLDP optional TLV + trailing padding round-trips exactly', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:0e', smac: 'aa:bb:cc:dd:ee:ff', etherType: '88cc'}},
        {id: 'lldp', data: {tlvs: [
            {type: 1, value: '04aabbccddeeff'},
            {type: 2, value: '0501'},
            {type: 3, value: '003c'},
            {type: 5, value: '73774131'}, // System Name "swA1"
            {type: 0, value: ''}
        ], padding: 'deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const lldp: any = Layer(decoded, 'lldp').data
    assert.strictEqual(lldp.tlvs.length, 5)
    assert.strictEqual(lldp.tlvs[3].value, '73774131', 'System Name TLV value preserved')
    assert.strictEqual(lldp.padding, 'deadbeef', 'padding after the End TLV is preserved verbatim')
})

// Negative: the TLV length is a 9-bit field (max 511 bytes). Crafting a value longer than 511 bytes
// must clamp the written value and record an error rather than silently wrapping the length modulo 512
// (which would set a bogus small length and corrupt every following TLV).
test('LLDP oversized TLV value: length clamped to 511 with a recorded error', async (): Promise<void> => {
    const value: string = 'ab'.repeat(600) // 600 bytes > the 9-bit maximum of 511
    const encoded: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:0e', smac: 'aa:bb:cc:dd:ee:ff', etherType: '88cc'}},
        {id: 'lldp', data: {tlvs: [
            {type: 1, value: value},
            {type: 0, value: ''}
        ]}}
    ])
    const clamped = encoded.errors.filter((e): boolean => e.message.includes('Maximum TLV value length is 511 bytes'))
    assert.strictEqual(clamped.length, 1, 'an over-length TLV value must record exactly one clamp error')
    // Re-decode: the first TLV must carry exactly 511 bytes (not 600 % 512 = 88), proving the length
    // field was clamped in step with the written value so the following End TLV still parses.
    const decoded: CodecDecodeResult[] = await codec.decode(encoded.packet)
    const lldp: any = Layer(decoded, 'lldp').data
    assert.strictEqual(lldp.tlvs[0].type, 1)
    assert.strictEqual(lldp.tlvs[0].value.length / 2, 511, 'TLV value clamped to 511 bytes')
    assert.deepStrictEqual(lldp.tlvs[1], {type: 0, value: ''}, 'the End TLV still parses after the clamped TLV')
})

// A frame whose last TLV claims a length that overruns the frame: decode must survive (never throw)
// and the truncated bytes are preserved as padding so the input still round-trips.
test('LLDP truncated final TLV: decode survives and round-trips', async (): Promise<void> => {
    const full: Buffer = LoadPacket('lldp/basic').buffer
    // Cut so the TTL TLV header survives but its 2 value bytes are gone: the length-overrun guard must
    // stop the walk and preserve the dangling header bytes as padding (14 eth + 21 payload = 35).
    const truncated: Buffer = full.subarray(0, 35)
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(truncated)
    AssertLayers(decoded, ['eth', 'lldp'])
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), truncated.toString('hex'), 'truncated frame round-trips via padding')
})
