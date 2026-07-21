import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// FCoE (FC-BB-5, ethertype 0x8906) — a minimal frame: 14-byte FCoE header (version + reserved + SOF),
// an encapsulated 32-byte FC frame, and a 4-byte EOF trailer. Byte-perfect round-trip.
test('FCoE: header + FC frame + trailer + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('fcoe/basic').buffer)
    AssertLayers(decoded, ['eth', 'fcoe'])
    const fcoe: any = Layer(decoded, 'fcoe').data
    assert.strictEqual(fcoe.version, 0, 'FCoE version 0')
    assert.strictEqual(fcoe.reservedFlags, 0, 'reserved low nibble of byte 0')
    assert.strictEqual(fcoe.reserved, '000000000000000000000000', '12 reserved bytes')
    assert.strictEqual(fcoe.sof, 0x2e, 'SOFi3')
    assert.strictEqual(fcoe.fcFrame, '220000ef000000ee082900000000000003e8ffff00000000deadbeef00000000', 'encapsulated FC frame (header + payload + CRC)')
    assert.strictEqual(fcoe.eof, 0x42, 'EOFt')
    assert.strictEqual(fcoe.eofReserved, '000000', '3 reserved trailer bytes')
})

// Crafting: an FCoE frame assembled from field values (SOFn3 / EOFn) must decode back to the same
// fields and re-encode byte-identically — the delimiters and FC frame are carried verbatim.
test('FCoE faithfully encodes a crafted frame', async (): Promise<void> => {
    const fcFrame: string = '00' + '00'.repeat(23) + 'cafebabe' + '00000000' // 24-byte FC hdr + 4 payload + 4 CRC
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '0e:fc:00:00:00:01', smac: '0e:fc:00:00:00:02', etherType: '8906'}},
        {id: 'fcoe', data: {version: 0, sof: 0x36, fcFrame: fcFrame, eof: 0x41, eofReserved: '000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'fcoe'])
    const fcoe: any = Layer(decoded, 'fcoe').data
    assert.strictEqual(fcoe.sof, 0x36, 'SOFn3')
    assert.strictEqual(fcoe.fcFrame, fcFrame, 'FC frame carried verbatim')
    assert.strictEqual(fcoe.eof, 0x41, 'EOFn')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a non-FCoE EtherType must NOT be claimed as FCoE, and a truncated FCoE frame must survive
// decode without throwing.
test('FCoE rejects a non-0x8906 EtherType, and truncation survives', async (): Promise<void> => {
    // EtherType 0x0842 (Wake-on-LAN), unsigned bytes that collide with no content heuristic.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '0e:fc:00:00:00:01', smac: '0e:fc:00:00:00:02', etherType: '0842'}},
        {id: 'raw', data: {data: '000000000000000000000000002e2200000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'fcoe'), 'wrong EtherType must not be claimed as FCoE')

    const full: Buffer = LoadPacket('fcoe/basic').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})
