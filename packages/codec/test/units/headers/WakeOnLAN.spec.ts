import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Wake-on-LAN magic packet (EtherType 0x0842): sync stream (ff x6) + target MAC x16 (+ optional password).
test('WoL magic packet: sync stream + 16x MAC + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('wol/magic').buffer)
    AssertLayers(decoded, ['eth', 'wol'])
    const wol: any = Layer(decoded, 'wol').data
    assert.strictEqual(wol.syncStream, 'ffffffffffff', 'all-ones sync stream')
    assert.strictEqual(wol.targetMac, '00:11:22:33:44:55', 'target MAC from the first repetition')
    assert.strictEqual(wol.password, '', 'no SecureOn password')
})

// Crafting: a magic packet with a 6-byte SecureOn password. The trailing password bytes are kept
// verbatim, and the target MAC is re-emitted 16 times, so the crafted frame round-trips byte-identically.
test('WoL faithfully carries a SecureOn password and re-emits the 16x MAC block', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:aa:bb:cc:dd:ee', etherType: '0842'}},
        {id: 'wol', data: {syncStream: 'ffffffffffff', targetMac: 'de:ad:be:ef:00:01', password: 'a1b2c3d4e5f6'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'wol'])
    const wol: any = Layer(decoded, 'wol').data
    assert.strictEqual(wol.targetMac, 'de:ad:be:ef:00:01', 'target MAC')
    assert.strictEqual(wol.password, 'a1b2c3d4e5f6', 'SecureOn password kept verbatim')
    // The 96-byte MAC block is 16 identical repetitions of the target MAC.
    assert.strictEqual(packet.toString('hex').indexOf('deadbeef0001'.repeat(16)) > -1, true, '16x MAC block')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: an EtherType 0x0842 frame whose 6-byte sync stream is NOT all-ones must NOT be claimed as WoL
// (falls through to raw); and a truncated magic packet must survive decode without throwing.
test('WoL rejects a non-all-ones sync stream on EtherType 0x0842, and truncation survives', async (): Promise<void> => {
    // A well-formed frame length (>=102 payload) but the sync stream begins 00 — not the WoL signature.
    const badSync: string = '00ffffffffff' + '001122334455'.repeat(16)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:aa:bb:cc:dd:ee', etherType: '0842'}},
        {id: 'raw', data: {data: badSync}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'wol'), 'non-all-ones sync must not be claimed as WoL')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('wol/magic').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 40))
})

// Regression (was a byte-perfect break): a 0x0842 frame with an all-ones sync stream but NON-identical
// MAC repetitions is not a valid magic packet — match() rejects it (the block cannot round-trip when
// reconstructed from a single MAC), so it falls to raw and round-trips byte-for-byte via RawData.
test('WoL: non-identical MAC repetitions are not claimed (fall to raw), preserving byte-perfect', async (): Promise<void> => {
    // 6xFF sync, then 15 reps of 00:11:22:33:44:55 + a differing 16th rep — not a magic packet.
    const block: string = 'ffffffffffff' + '001122334455'.repeat(15) + '0011223344ff'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:aa:bb:cc:dd:ee', etherType: '0842'}},
        {id: 'raw', data: {data: block}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'wol'), 'non-identical reps must not be claimed as WoL')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect via raw')
})
