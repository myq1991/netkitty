import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'

test('UDP baseline: field decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('udp/baseline').buffer)
    const udp: any = Layer(decoded, 'udp').data
    assert.strictEqual(udp.srcport, 19808)
    assert.strictEqual(udp.dstport, 19808)
    assert.strictEqual(udp.length, 24)
    assert.strictEqual(udp.checksum, 35163)
})

test('UDP NetBIOS datagram: round-trip', async (): Promise<void> => {
    await AssertRoundTrip(LoadPacket('udp/netbios').buffer)
})

// KNOWN BUG: decode throws on a packet truncated inside the UDP header.
// Decode must never throw by design.
test('UDP truncated mid-header: decode survives without throwing', async (): Promise<void> => {
    await AssertDecodeSurvives(LoadPacket('udp/baseline').buffer.subarray(0, 30))
})

// The crafted fixture stores the RFC-correct checksum (0xFFFF) already, so a plain round-trip
// (which re-encodes the stored non-zero value verbatim) reproduces the bytes and passes. The bug
// only shows when the checksum is recomputed from scratch.
test('UDP checksum-zero fixture: byte-perfect round-trip of stored 0xFFFF', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('udp/checksum-zero').buffer)
    assert.strictEqual((Layer(decoded, 'udp').data as any).checksum, 0xFFFF)
})

// BUG #3 (REAL, deterministically triggered by this fixture): when the computed UDP checksum is
// 0x0000 it must be transmitted as 0xFFFF (RFC 768), because 0 in the wire field means
// "no checksum". UDP.ts:58 returns `(~sum) & 0xFFFF`, which yields 0 whenever the ones-complement
// sum folds to 0xFFFF, and never flips it to 0xFFFF.
// This fixture (payload 15da over sip/dip 192.168.0.1/.2) is constructed so the sum folds to
// exactly 0xFFFF. Setting checksum = 0 forces the encoder down the recompute path.
// Correct behaviour: re-decoded checksum === 0xFFFF. The bug writes 0x0000.
test('UDP recomputed checksum of zero must be transmitted as 0xFFFF', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('udp/checksum-zero').buffer)
    const udp: any = Layer(decoded, 'udp').data
    udp.checksum = 0   // 0 => force the encoder to recompute the checksum
    const encoded = await codec.encode(decoded)
    const redecoded: CodecDecodeResult[] = await codec.decode(encoded.packet)
    assert.strictEqual((Layer(redecoded, 'udp').data as any).checksum, 0xFFFF,
        'a computed checksum of 0 must be sent as 0xFFFF, not 0x0000 (RFC 768)')
})
