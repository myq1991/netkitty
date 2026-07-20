import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'

test('TCP baseline: field decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tcp/baseline').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp'])
    const tcp: any = Layer(decoded, 'tcp').data
    assert.strictEqual(tcp.srcport, 65319)
    assert.strictEqual(tcp.dstport, 443)
    assert.strictEqual(tcp.seq, 1676493975)
    assert.strictEqual(tcp.checksum, 5855)
    assert.strictEqual(tcp.hdrLen, 44, 'header with options must decode full data-offset length')
})

test('TCP with HTTP payload: payload decodes as http (now registered) + round-trip', async (): Promise<void> => {
    // Previously HTTP had no codec so this GET fell to raw; with the HTTP header registered it is now
    // decoded as an http layer. The TCP round-trip is byte-perfect either way.
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tcp/http-get').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'http'])
})

test('TCP truncated mid-header: decode survives', async (): Promise<void> => {
    await AssertDecodeSurvives(LoadPacket('tcp/baseline').buffer.subarray(0, 40))
})

// BUG #1 (REAL): TCP options 32-bit alignment padding is dead code.
// TCP.ts:930-934 guards padding with `const headerBitLength = this.length * 8; if (headerBitLength % 4)`.
// A byte count times 8 is always divisible by 4, so the condition is always false and the
// padding branch never runs. Combined with hdrLen being written as Math.floor(length/4)
// (TCP.ts:239/243), a header whose options do not land on a 4-byte boundary produces a Data
// Offset that is rounded DOWN and does not cover all option bytes. Per RFC 9293 the TCP header
// (Data Offset * 4) must be a multiple of 4 and must cover every option byte, padding with
// End-of-Option-List/zeroes as needed.
// Repro: replace the options with MSS(4 bytes) + Window-Scale(3 bytes) = 7 option bytes, so the
// header is 20 + 7 = 27 bytes. Correct encoding pads to 28 (Data Offset = 7). The bug encodes
// Data Offset = 6 (24 bytes), truncating the Window-Scale option on re-decode.
test('TCP unaligned options must be padded to a 32-bit boundary', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('tcp/baseline').buffer)
    const tcp: any = Layer(decoded, 'tcp').data
    tcp.options = [
        {option: 'MSS', mss: 1460},
        {option: 'Window-Scale', shift: 7}
    ]
    tcp.hdrLen = 0        // 0 => auto-recompute Data Offset from the encoded header length
    tcp.checksum = 0      // 0 => auto-recompute checksum over the new header
    const encoded = await codec.encode(decoded)
    // Read the Data Offset straight off the wire: ethernet(14) + IPv4 header, then TCP byte 12.
    const tcpStart: number = 14 + (encoded.packet[14] & 0x0f) * 4
    const dataOffsetWords: number = encoded.packet[tcpStart + 12] >> 4
    const headerBytes: number = dataOffsetWords * 4
    // 20 base + 7 option bytes (MSS 4 + Window-Scale 3), padded to the next 32-bit boundary => 28.
    assert.strictEqual(headerBytes, 28, 'Data Offset must cover all option bytes and be 4-byte aligned')
    assert.ok(headerBytes >= 27, 'Data Offset must not truncate the option area')
    assert.strictEqual(headerBytes % 4, 0, 'TCP header length must be a multiple of 4 (RFC 9293)')
})

// RFC 5482: the User Timeout option is Kind=28, Length=4, with a single 16-bit value whose top
// bit is Granularity and low 15 bits are the timeout. It was previously emitted as a malformed
// 5-byte option (Length=5, 16-bit timeout + separate granularity byte).
test('TCP User Timeout option (RFC 5482): Length=4, G+15-bit timeout, round-trips', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tcp/uto-option').buffer)
    const tcp: any = Layer(decoded, 'tcp').data
    const uto: any = tcp.options.find((o: any): boolean => o.option === 'UTO')
    assert.ok(uto, 'UTO option must decode')
    assert.strictEqual(uto.granularity, 1)
    assert.strictEqual(uto.timeout, 100)
})
