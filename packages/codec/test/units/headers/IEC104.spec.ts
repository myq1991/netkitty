import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, Decode, Layer} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'

test('IEC104 I-format frame with ASDU: decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('iec104/i-frame').buffer)
    const frame: any = Layer(decoded, 'IEC104_I_Frame').data
    assert.strictEqual(frame.startByte, 104)
    assert.strictEqual(frame.apduLength, 14)
    assert.strictEqual(frame.apciType, 'I-Format')
})

test('IEC104 S-format frame: decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('iec104/s-frame').buffer)
    const frame: any = Layer(decoded, 'IEC104_S_Frame').data
    assert.strictEqual(frame.apduLength, 4)
    assert.strictEqual(frame.apciType, 'S-Format')
    assert.strictEqual(frame.controlField, '01001a00')
})

test('IEC104 U-format TESTFR act frame: decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('iec104/u-frame').buffer)
    const frame: any = Layer(decoded, 'IEC104_U_Frame').data
    assert.strictEqual(frame.apciType, 'U-Format Type:Test Frame Activation')
    assert.strictEqual(frame.controlField, '43000000')
})

// KNOWN BUG: decode compares uppercase '0B000000' against lowercase hex output,
// so the STARTDT con branch is unreachable - apciType falls back to the raw hex
// string and an "Illegal acpiType!" error is recorded.
test('IEC104 U-format STARTDT con frame: apciType decodes correctly', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('iec104/u-frame-startdt-con').buffer)
    const layer: CodecDecodeResult = Layer(decoded, 'IEC104_U_Frame')
    assert.strictEqual(layer.errors.length, 0, 'a legal STARTDT con frame must not record errors')
    assert.notStrictEqual((layer.data as any).apciType, '0b000000', 'apciType must not fall back to raw hex')
})

test('IEC104 truncated before APCI: decode survives (falls back to TCP payload)', async (): Promise<void> => {
    await AssertDecodeSurvives(LoadPacket('iec104/i-frame').buffer.subarray(0, 40))
})

// ---------------------------------------------------------------------------
// Header-audit report: 5 suspected bugs, one executable test each.
// ---------------------------------------------------------------------------

// BUG 1 (REAL) - apciType reads the wrong control octet.
// IEC104_I_Frame.ts:59 decode does readBits(5, 1, 7, 1) and :77/:81 encode does
// writeBits(5, 1, 7, 1, ...): byte offset 5 is control-field octet 4 = the HIGH
// 8 bits of the receive sequence number N(R), not the I/S/U format selector.
// The I-format bit is bit0 of control-field octet 1 (byte offset 2), so the read
// should be readBits(2, 1, 7, 1). A perfectly legal I-frame whose N(R) >= 128
// sets the LSB of octet 4 (N(R) high byte), so decode takes the default branch,
// records "Illegal acpiType!" and stores a numeric apciType instead of 'I-Format'.
// Fixture i-frame-nr-200 is a legal I-frame with Tx=0, Rx(N(R))=200 (tshark: "<- I (0,200)").
test('IEC104 I-frame with N(R)=200 must decode as I-Format without error', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await Decode(LoadPacket('iec104/i-frame-nr-200').buffer)
    const layer: CodecDecodeResult = Layer(decoded, 'IEC104_I_Frame')
    const illegal: boolean = layer.errors.some((e): boolean => e.message.includes('Illegal acpiType'))
    assert.strictEqual(illegal, false, 'a legal I-frame with N(R)=200 must not be flagged as an illegal APCI type')
    assert.strictEqual((layer.data as any).apciType, 'I-Format', 'apciType must be I-Format regardless of N(R) value')
})

// BUG 2 (REAL) - sqBit encode writes the SQ bit into the APDU Length octet.
// IEC104_I_Frame.ts:108 decode reads the SQ bit correctly from byte offset 7
// (the VSQ octet) via readBits(7, 1, 0, 1), but :116 encode does
// writeBits(1, 1, 0, 1, bit): byte offset 1 is the APDU Length field. When SQ=1
// the length octet gets OR'd with 0x80 (+128) and the real SQ bit in the VSQ
// octet is never written, so a decode->encode round-trip cannot reproduce a
// legal SQ=1 frame. Correct encode target is byte offset 7: writeBits(7, 1, 0, 1, bit).
// Fixture i-frame-sq1 has VSQ=0x81 (tshark: "SQ: True", NumIx=1).
test('IEC104 SQ=1 frame must round-trip without corrupting the APDU Length octet', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('iec104/i-frame-sq1').buffer)
    const frame: any = Layer(decoded, 'IEC104_I_Frame').data
    assert.strictEqual(frame.sqBit, 1, 'SQ bit must decode as 1')
    assert.strictEqual(frame.apduLength, 14, 'APDU length must stay 14 and not absorb the SQ bit (+128)')
})

// BUG 3 (REAL) - a 3-octet Information Object Address is decoded with readUInt16LE.
// IEC104_I_Frame.ts:3544 reads readBytes(..., 3).readUInt16LE(): it fetches 3
// bytes but decodes only the low 2, dropping octet 3 (bits 16-23). encode
// (:5872 etc.) correctly writes all 3 with writeUIntLE(addr, 0, 3), so any IOA
// > 65535 is truncated on decode and the round-trip is asymmetric. Correct decode
// is readUIntLE(0, 3). Fixture i-frame-ioa-65536 has IOA octets 00 00 01
// (LE = 0x010000 = 65536) (tshark: "IOA=65536").
test('IEC104 3-octet IOA of 65536 must decode fully (all 3 address octets)', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await Decode(LoadPacket('iec104/i-frame-ioa-65536').buffer)
    const frame: any = Layer(decoded, 'IEC104_I_Frame').data
    assert.strictEqual(frame.IOA[0].address, 65536, 'IOA must be 65536, not the low 16 bits (0)')
})

// BUG 4 (REAL) - M_DP_NA_1 (DIQ) quality flags are decoded one bit too high.
// IEC104_I_Frame.ts decode (:3585-3588) reads BL/SB/NT/IV from readBits indices
// 4/3/2/1, but encode (:5896-5899) and SIQ decode (:3554-3557) use indices
// 3/2/1/0. The decode is shifted one bit toward the MSB, so IV is read from the
// NT bit and the true IV bit (index 0) is ignored; a round-trip therefore drifts
// the quality bits. Fixture i-frame-mdp-iv is an M_DP_NA_1 with DIQ=0x80, i.e.
// IV=1 and DPI=BL=SB=NT=0 (tshark: "IV: Invalid", "DPI: 0").
test('IEC104 M_DP_NA_1 DIQ=0x80 must decode as IV=1 with all other flags 0', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await Decode(LoadPacket('iec104/i-frame-mdp-iv').buffer)
    const dp: any = (Layer(decoded, 'IEC104_I_Frame').data as any).IOA[0]
    assert.strictEqual(dp.IV, 1, 'IV (DIQ bit7) must be 1')
    assert.strictEqual(dp.DPI, 0, 'DPI (DIQ bits0-1) must be 0')
    assert.strictEqual(dp.BL, 0, 'BL must be 0')
    assert.strictEqual(dp.SB, 0, 'SB must be 0')
    assert.strictEqual(dp.NT, 0, 'NT must be 0')
})

// BUG 5 (REAL) - the IEC104 heuristic match is too permissive.
// IEC104_I_Frame.ts:7357 match() only checks that the first payload byte is 0x68
// and two control bits; it never verifies the frame rides on TCP port 2404. As a
// registered content-heuristic codec (no MATCH_KEYS), it is offered every TCP
// payload, so any payload starting with 0x68 ('h') and an even control octet is
// misclassified as an IEC104 I-frame. Fixture tcp-0x68-not-iec104 is ordinary TCP
// on port 80 carrying ASCII "http-not-iec104." (tshark dissects it as plain TCP,
// not iec60870_104).
test('IEC104 must not claim a non-2404 TCP payload that merely starts with 0x68', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await Decode(LoadPacket('iec104/tcp-0x68-not-iec104').buffer)
    const ids: string[] = decoded.map((r: CodecDecodeResult): string => r.id)
    assert.ok(ids.includes('tcp'), 'the packet must still decode its TCP layer')
    assert.ok(!ids.includes('IEC104_I_Frame'), 'a port-80 0x68 payload must not be decoded as IEC104')
})

// An unknown/unsupported ASDU type id cannot be structured. The raw-fallback must surface the
// unparsed ASDU bytes as a visible `raw` field (empty IOA + recorded errors) and reproduce the
// original bytes on re-encode. Previously decode pushed a bare hex string into IOA, which then
// failed Ajv validation on encode ("must be object") - i.e. the frame could not be re-encoded.
test('IEC104 unknown ASDU type id: unparsed ASDU surfaced as raw and round-trips', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('iec104/i-frame-unknown-typeid').buffer)
    const frame: any = Layer(decoded, 'IEC104_I_Frame')
    assert.ok(frame.data.raw, 'the un-parseable ASDU bytes must be visible as raw')
    assert.deepStrictEqual(frame.data.IOA, [], 'IOA must be empty (no structured objects) for an unknown type id')
    assert.ok(frame.errors.some((e: any): boolean => e.message === 'Illegal Type Id'), 'the unknown type id must be recorded as an error')
})

// Type 31 (M_DP_TB_1) DIQ quality bits must use the same positions as SIQ/type-3 DIQ
// (BL=bit4, SB=bit5, NT=bit6, IV=bit7). Previously they were read one bit too high AND the
// decoder/encoder disagreed, corrupting SB/NT/IV across a round-trip.
test('IEC104 M_DP_TB_1 (type 31) DIQ=0x80 decodes IV=1, others 0, and round-trips', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('iec104/i-frame-mdp-tb').buffer)
    const dp: any = (Layer(decoded, 'IEC104_I_Frame').data as any).IOA[0]
    assert.strictEqual(dp.IV, 1, 'IV (DIQ bit7) must be 1')
    assert.strictEqual(dp.DPI, 0)
    assert.strictEqual(dp.BL, 0)
    assert.strictEqual(dp.SB, 0)
    assert.strictEqual(dp.NT, 0)
})

// SQ=1 (sequence of information elements): a single base IOA followed by N addressless elements
// whose addresses increment from the base. Previously only the SQ=0 layout (address per element)
// was produced, so SQ=1 frames decoded with wrong addresses and misaligned element data.
test('IEC104 SQ=1 multi-object frame: incrementing addresses + aligned elements + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('iec104/i-frame-sq1-multi').buffer)
    const frame: any = Layer(decoded, 'IEC104_I_Frame').data
    assert.strictEqual(frame.sqBit, 1)
    assert.strictEqual(frame.numberOfObject, 3)
    assert.deepStrictEqual(frame.IOA.map((o: any): number => o.address), [1, 2, 3], 'addresses must increment from the base')
    assert.deepStrictEqual(frame.IOA.map((o: any): number => o.SPI), [1, 0, 0])
    assert.deepStrictEqual(frame.IOA.map((o: any): number => o.IV), [0, 0, 1])
})

// The send/receive sequence numbers N(S)/N(R) (15-bit, little-endian, <<1) are exposed for
// analysis. S-frames exist specifically to acknowledge N(R).
test('IEC104 I-frame exposes N(S)/N(R) sequence numbers', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await Decode(LoadPacket('iec104/i-frame-nr-200').buffer)
    const frame: any = Layer(decoded, 'IEC104_I_Frame').data
    assert.strictEqual(frame.rxSequence, 200, 'N(R) must decode to 200')
    assert.strictEqual(frame.txSequence, 0, 'N(S) must decode to 0')
})

test('IEC104 S-frame exposes the acknowledged N(R)', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await Decode(LoadPacket('iec104/s-frame').buffer)
    const frame: any = Layer(decoded, 'IEC104_S_Frame').data
    assert.strictEqual(frame.rxSequence, 13, 'N(R) from control 01001a00 must be 13')
})

// SCO/DCO/RCO command qualifier QU is a 5-bit field (IEC bits 2-6); it was read as a single bit.
test('IEC104 single command (type 45): QU decodes as a 5-bit qualifier and round-trips', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('iec104/i-frame-sco-qu').buffer)
    assert.strictEqual((Layer(decoded, 'IEC104_I_Frame').data as any).IOA[0].QU, 5, 'QU (SCO octet 0x14) must be 5')
})

// BSI (32-bit binary state information) is a little-endian information element.
test('IEC104 bitstring (type 7): BSI decodes little-endian and round-trips', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('iec104/i-frame-bsi').buffer)
    assert.strictEqual((Layer(decoded, 'IEC104_I_Frame').data as any).IOA[0].BSI, 0x04030201, 'BSI octets 01020304 LE = 0x04030201')
})
