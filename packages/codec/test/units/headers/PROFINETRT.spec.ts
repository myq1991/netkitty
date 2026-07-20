import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, LayerIds, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// The `data` field of the fixture: everything after the 2-byte FrameID — 40 IO-data bytes (0x01..0x28)
// followed by the 4-byte APDU-Status (CycleCounter 0x1234, DataStatus 0x35, TransferStatus 0x00).
const FIXTURE_DATA: string = '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272812343500'

// A hand-crafted cyclic PROFINET-RT frame over Ethernet II (EtherType 0x8892): FrameID 0x8000 then the
// IO data + APDU-Status, exactly 60 bytes (the Ethernet minimum). Byte-perfect round-trip.
test('PROFINET-RT cyclic frame: FrameID decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('pnio/rt').buffer)
    AssertLayers(decoded, ['eth', 'pnio'])
    const pnio: any = Layer(decoded, 'pnio').data
    assert.strictEqual(pnio.frameId, 0x8000, 'cyclic RT_CLASS_1/2 FrameID 0x8000')
    assert.strictEqual(pnio.data, FIXTURE_DATA, 'everything after FrameID kept verbatim as hex')
})

// Craft a frame from scratch (acyclic alarm FrameID 0xFC01) and require a byte-perfect
// encode → decode → re-encode round-trip.
test('PROFINET-RT crafted frame: encode → decode → re-encode is byte-identical', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:0e:cf:00:00:00', smac: 'aa:bb:cc:dd:ee:ff', etherType: '8892'}},
        {id: 'pnio', data: {frameId: 0xfc01, data: 'aabbccdd'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'pnio'])
    const pnio: any = Layer(decoded, 'pnio').data
    assert.strictEqual(pnio.frameId, 0xfc01)
    assert.strictEqual(pnio.data, 'aabbccdd')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// A frame truncated mid-data: decode must survive (never throw) and the whole input must still
// round-trip — the `data` field simply carries fewer bytes.
test('PROFINET-RT truncated frame: decode survives and round-trips', async (): Promise<void> => {
    const full: Buffer = LoadPacket('pnio/rt').buffer
    // Keep the 14-byte Ethernet header + 2-byte FrameID + 10 data bytes, dropping the rest.
    const truncated: Buffer = full.subarray(0, 26)
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(truncated)
    AssertLayers(decoded, ['eth', 'pnio'])
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), truncated.toString('hex'), 'truncated frame round-trips')
})

// A non-0x8892 Ethernet frame must NOT be claimed as pnio: an unknown EtherType (0x9999) has no codec,
// so it falls through to the RawData catch-all rather than being decoded as PROFINET-RT.
test('PROFINET-RT does not claim a non-0x8892 Ethernet frame', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:0e:cf:00:00:00', smac: 'aa:bb:cc:dd:ee:ff', etherType: '9999'}},
        {id: 'raw', data: {data: '80000102030405060708'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!LayerIds(decoded).includes('pnio'), 'a 0x9999 frame must not be decoded as pnio')
    AssertLayers(decoded, ['eth', 'raw'])
})
