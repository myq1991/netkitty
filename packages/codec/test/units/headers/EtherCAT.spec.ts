import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, LayerIds, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Real-shaped fixture: an EtherCAT command frame (EtherType 0x88A4) with one datagram, padded to the
// 60-byte Ethernet minimum. The Length-bounded datagram is kept verbatim as `data`; the trailing padding
// falls to RawData. The whole 60-byte frame must round-trip byte-for-byte.
test('EtherCAT command frame: decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ecat/cmd').buffer)
    AssertLayers(decoded, ['eth', 'ecat', 'raw'])
    const ecat: any = Layer(decoded, 'ecat').data
    assert.strictEqual(ecat.type, 1, 'Type = 1 (EtherCAT command / DLPDU)')
    assert.strictEqual(ecat.length, 16, 'Length = 16 datagram bytes')
    assert.strictEqual(ecat.reserved, 0, 'Reserved bit preserved as 0')
    // The 16 datagram bytes (10-byte header + 4 data + 2 WKC) kept verbatim.
    assert.strictEqual(ecat.data, '01000000001004000000010203040100', 'datagram kept verbatim as hex')
})

// Craft an EtherCAT header from scratch and require a byte-perfect encode→decode→re-encode. Also confirm
// the 2 header bytes are written LITTLE-ENDIAN: type=1, length=4 → h=0x1004 → on-wire bytes 04 10.
test('EtherCAT crafted little-endian header: encode → decode → re-encode is byte-identical', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '0a:0b:0c:0d:0e:0f', smac: '11:22:33:44:55:66', etherType: '88a4'}},
        {id: 'ecat', data: {type: 1, length: 4, data: '01020304', reserved: 0}}
    ])
    // The EtherCAT header sits right after the 14-byte Ethernet header. h = 0x1004 → little-endian 04 10.
    assert.strictEqual(packet.subarray(14, 16).toString('hex'), '0410', 'header word 0x1004 written little-endian as 04 10')
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ecat'])
    const ecat: any = Layer(decoded, 'ecat').data
    assert.strictEqual(ecat.type, 1)
    assert.strictEqual(ecat.length, 4)
    assert.strictEqual(ecat.data, '01020304')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'crafted frame round-trips byte-for-byte')
})

// Metamorphic: a Type value with the high bit set must round-trip through the 4-bit field, and a Length
// beyond the 11-bit maximum (0x7FF) must be clamped and recorded rather than wrapping into the Type bits.
test('EtherCAT high-bit type round-trips; over-range length is clamped + recorded', async (): Promise<void> => {
    // (a) Type = 0xC (high bit of the 4-bit field set), Length matching a 5-byte datagram → round-trip.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '0a:0b:0c:0d:0e:0f', smac: '11:22:33:44:55:66', etherType: '88a4'}},
        {id: 'ecat', data: {type: 0xC, length: 5, data: 'aabbccddee', reserved: 0}}
    ])
    // h = (5) | (0xC << 12) = 0xC005 → little-endian 05 c0.
    assert.strictEqual(packet.subarray(14, 16).toString('hex'), '05c0', 'h=0xC005 written little-endian as 05 c0')
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ecat'])
    const ecat: any = Layer(decoded, 'ecat').data
    assert.strictEqual(ecat.type, 0xC, 'Type = 0xC survives the 4-bit field')
    assert.strictEqual(ecat.length, 5)
    assert.strictEqual(ecat.data, 'aabbccddee')

    // (b) Length = 0x800 (2048) exceeds the 11-bit maximum → clamp to 0x7FF and record exactly one error.
    const encoded: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '0a:0b:0c:0d:0e:0f', smac: '11:22:33:44:55:66', etherType: '88a4'}},
        {id: 'ecat', data: {type: 1, length: 0x800, data: '01020304', reserved: 0}}
    ])
    const clamped = encoded.errors.filter((e): boolean => e.message.includes('Maximum value is 2047'))
    assert.strictEqual(clamped.length, 1, 'an over-range Length must record exactly one clamp error')
    const redecoded: CodecDecodeResult[] = await codec.decode(encoded.packet)
    assert.strictEqual(Layer(redecoded, 'ecat').data.length, 0x7FF, 'Length clamped to the 11-bit maximum 0x7FF')
})

// A truncated frame (datagram cut short) must survive decode and still round-trip, and a non-0x88A4
// Ethernet frame must NOT be claimed by the EtherCAT header.
test('EtherCAT truncated frame survives + round-trips; non-0x88A4 is not claimed', async (): Promise<void> => {
    // Cut to 20 bytes: 14-byte Ethernet + 2-byte EtherCAT header (Length=16) + only 4 datagram bytes.
    // The data read is clamped to the captured bytes, so decode survives and the frame round-trips.
    const truncated: Buffer = LoadPacket('ecat/cmd').buffer.subarray(0, 20)
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(truncated)
    AssertLayers(decoded, ['eth', 'ecat'])
    assert.strictEqual(Layer(decoded, 'ecat').data.data, '01000000', 'clamped datagram bytes preserved verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), truncated.toString('hex'), 'truncated frame round-trips')

    // A frame with a different EtherType (0x88B5) must not be claimed as EtherCAT.
    const other: Buffer = Buffer.from('0a0b0c0d0e0f11223344556688b501020304', 'hex')
    const otherDecoded: CodecDecodeResult[] = await codec.decode(other)
    assert.ok(!LayerIds(otherDecoded).includes('ecat'), 'a non-0x88A4 Ethernet frame must not be decoded as EtherCAT')
})
