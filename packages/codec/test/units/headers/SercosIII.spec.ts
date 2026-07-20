import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Sercos III (ethertype 0x88CD) MDT0 carrying the Master Sync Telegram (MST). The 6-byte header —
// Telegram Type byte (channel/type/cycle-count-valid/telegram number) + Phase field byte + CRC32 —
// is structured; the per-device body is kept verbatim. Byte-perfect decode→encode.
test('Sercos III MDT0: MST header fields + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('sercos3/mdt0').buffer)
    AssertLayers(decoded, ['eth', 'sercos3'])
    const s: any = Layer(decoded, 'sercos3').data
    assert.strictEqual(s.channel, 0, 'P-Telegram')
    assert.strictEqual(s.telegramType, 0, 'MDT')
    assert.strictEqual(s.cycleCountValid, 1, 'cycle count valid')
    assert.strictEqual(s.reserved, 0, 'byte-0 reserved bit')
    assert.strictEqual(s.telegramNumber, 0, 'telegram 0')
    assert.strictEqual(s.phase, 2, 'communication phase CP2')
    assert.strictEqual(s.cycleCnt, 0, 'cycle count')
    assert.strictEqual(s.crc32, '12345678', 'MST CRC32 honored verbatim')
})

// AT0 (Acknowledge Telegram) — the same EtherType, distinguished only by the Telegram Type bit (0x40).
test('Sercos III AT0: telegram type bit distinguishes AT from MDT + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('sercos3/at0').buffer)
    AssertLayers(decoded, ['eth', 'sercos3'])
    const s: any = Layer(decoded, 'sercos3').data
    assert.strictEqual(s.telegramType, 1, 'AT')
    assert.strictEqual(s.telegramNumber, 0, 'telegram 0')
    assert.strictEqual(s.phase, 2, 'communication phase CP2')
    assert.strictEqual(s.crc32, '90abcdef', 'MST CRC32 honored verbatim')
})

// Crafting: a minimal MDT is assembled from header fields only. The Phase field byte is reassembled from
// the disjoint phase (0x8f) and cycle-count (0x70) sub-values, and the byte-0 reserved bit is preserved;
// the crafted frame must re-encode byte-identically.
test('Sercos III faithfully encodes a crafted telegram and reassembles the phase byte', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:11:11:11:11:11', smac: '00:11:22:33:44:55', etherType: '88cd'}},
        {id: 'sercos3', data: {
            channel: 1, telegramType: 0, cycleCountValid: 1, reserved: 1, telegramNumber: 3,
            phase: 2, cycleCnt: 3, crc32: 'aabbccdd', data: 'cafe'
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'sercos3'])
    const s: any = Layer(decoded, 'sercos3').data
    assert.strictEqual(s.channel, 1, 'S-Telegram')
    assert.strictEqual(s.telegramType, 0, 'MDT')
    assert.strictEqual(s.reserved, 1, 'byte-0 reserved bit preserved')
    assert.strictEqual(s.telegramNumber, 3)
    assert.strictEqual(s.phase, 2, 'phase decoded back from reassembled byte 1')
    assert.strictEqual(s.cycleCnt, 3, 'cycle count decoded back from reassembled byte 1')
    // byte 1 must be (phase & 0x8f) | (cycleCnt << 4) = 0x02 | 0x30 = 0x32
    assert.strictEqual(packet[14 + 1], 0x32, 'phase byte reassembled from disjoint phase + cycleCnt')
    assert.strictEqual(s.crc32, 'aabbccdd', 'CRC32 honored verbatim')
    assert.strictEqual(s.data, 'cafe')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a 0x88CD frame shorter than the 6-byte MST header must NOT be claimed as Sercos III (it
// falls through to raw); and a truncated Sercos III frame must survive decode without throwing.
test('Sercos III requires the 6-byte header, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:11:11:11:11:11', smac: '00:11:22:33:44:55', etherType: '88cd'}},
        // only 4 payload bytes — below the 6-byte MST header, so not Sercos III
        {id: 'raw', data: {data: '20021234'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'sercos3'), 'sub-header frame must not be claimed as Sercos III')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    // Truncating the per-device body (Ethernet header + MST header intact) still decodes and survives.
    const full: Buffer = LoadPacket('sercos3/mdt0').buffer
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 4))
    AssertLayers(survived, ['eth', 'sercos3'])
})
