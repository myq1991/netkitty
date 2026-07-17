import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../lib/codec/types/CodecDecodeResult'

test('IPv4 header with options (IHL > 5): field decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ipv4/with-options').buffer)
    const ipv4: any = Layer(decoded, 'ipv4').data
    assert.strictEqual(ipv4.version, 4)
    assert.strictEqual(ipv4.hdrLen, 60, 'options header must decode full IHL length (60 bytes)')
    assert.strictEqual(ipv4.sip, '127.0.0.1')
    assert.strictEqual(ipv4.dip, '127.0.0.1')
    assert.strictEqual(ipv4.protocol, 1)
    assert.strictEqual(ipv4.ttl, 64)
    assert.strictEqual(ipv4.length, 124)
})

test('IPv4 first fragment (MF=1): flags decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ipv4/fragment-first').buffer)
    const ipv4: any = Layer(decoded, 'ipv4').data
    assert.strictEqual(ipv4.flags.mf, 1)
    assert.strictEqual(ipv4.fragOffset, 0)
})

test('IPv4 non-first fragment (offset > 0): decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ipv4/fragment-last').buffer)
    const ipv4: any = Layer(decoded, 'ipv4').data
    assert.strictEqual(ipv4.flags.mf, 0)
    assert.ok(ipv4.fragOffset > 0, 'non-first fragment must have fragOffset > 0')
})

// KNOWN BUG: decode throws on a packet truncated inside the IPv4 header
// (BufferToIPv4 receives a short buffer). Decode must never throw by design.
test('IPv4 truncated mid-header: decode survives without throwing', async (): Promise<void> => {
    await AssertDecodeSurvives(LoadPacket('tcp/baseline').buffer.subarray(0, 24))
})

// BUG #2 (REAL): IPv4 options padding only ever adds a single byte.
// IPv4.ts:307-313 does `if (estimateHdrLen % 4) optionsBuffer = concat([optionsBuffer, [0x00]])`.
// One byte only aligns headers that are exactly 3 (mod 4) short. When the options length is
// 1 or 2 (mod 4), a single pad byte leaves the header still misaligned, and IHL is then written
// as Math.floor(length/4) (IPv4.ts:64/68), so the encoded IHL neither covers the option bytes
// nor is a multiple of 4 words. Per RFC 791 the header (IHL * 4) must be a 32-bit multiple that
// covers the padded options.
// Repro: a 1-byte options field (0x01 = NOP). Correct encoding pads it to 4 bytes -> IHL = 6
// (24-byte header). The bug pads to 2 bytes and writes IHL = 5 (20 bytes), dropping the option.
test('IPv4 options must be padded to a full 32-bit word', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('ipv4/with-options').buffer)
    const ipv4: any = Layer(decoded, 'ipv4').data
    ipv4.options = '01'    // single NOP option byte -> options length 1 (mod 4)
    delete ipv4.hdrLen     // absent => auto-recompute IHL (schema minimum is 20, so 0 is not allowed)
    delete ipv4.length     // absent => auto-recompute total length to match the shrunken header
    const encoded = await codec.encode(decoded)
    // Read the IHL nibble straight off the wire (ethernet header is 14 bytes, IPv4 starts at 14).
    const ihlWords: number = encoded.packet[14] & 0x0f
    const headerBytes: number = ihlWords * 4
    // 20 base + 1 option byte padded up to the next 32-bit word => 24-byte header (IHL = 6).
    assert.strictEqual(headerBytes, 24, 'IHL must cover the padded options and be a 32-bit multiple')
    assert.strictEqual(headerBytes % 4, 0, 'IPv4 header length must be a multiple of 4 (RFC 791)')
})
