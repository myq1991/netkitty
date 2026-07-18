import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'

test('GOOSE baseline: PDU field decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('goose/baseline').buffer)
    AssertLayers(decoded, ['eth', 'goose'])
    const goose: any = Layer(decoded, 'goose').data
    assert.strictEqual(goose.appid, 1)
    assert.strictEqual(goose.length, 145)
    assert.strictEqual(goose.reserved1.simulated, false)
    assert.strictEqual(goose.goosePdu.gocbRef, 'GEDeviceF650/LLN0$GO$gcb01')
    assert.strictEqual(goose.goosePdu.goID, 'F650_GOOSE1')
    assert.strictEqual(goose.goosePdu.datSet, 'GEDeviceF650/LLN0$GOOSE1')
    assert.strictEqual(goose.goosePdu.timeAllowedtoLive, 40000)
    assert.strictEqual(goose.goosePdu.t, '4066394167022397450', '8-byte timestamp keeps BigInt-string precision')
    assert.strictEqual(goose.goosePdu.stNum, 1)
    assert.strictEqual(goose.goosePdu.sqNum, 10)
    assert.strictEqual(goose.goosePdu.confRev, 1)
    assert.strictEqual(goose.goosePdu.numDatSetEntries, 8)
    assert.ok(Array.isArray(goose.goosePdu.allData) && goose.goosePdu.allData.length > 0)
    assert.deepStrictEqual(goose.goosePdu.allData[0], {dataType: 'Boolean', value: false})
})

test('GOOSE additional real frames: byte-perfect round-trip', async (): Promise<void> => {
    await AssertRoundTrip(LoadPacket('goose/baseline-2').buffer)
    await AssertRoundTrip(LoadPacket('goose/baseline-3').buffer)
})

test('VLAN-tagged GOOSE with Structure entries: layers + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('goose/vlan-structure').buffer)
    AssertLayers(decoded, ['eth', 'vlan', 'goose'])
})

test('GOOSE truncated PDU: decode survives and accumulates field errors', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(LoadPacket('goose/baseline').buffer.subarray(0, 30))
    const goose: CodecDecodeResult = Layer(decoded, 'goose')
    assert.ok(goose.errors.length > 0, 'truncated PDU must be reported via error accumulation')
})

// KNOWN BUG: reserved2 encode uses byte offset 4 (reserved1's offset) instead of 6,
// so encoding overwrites the whole reserved1 word - including the Simulated flag.
test('GOOSE edit workflow: set simulated=true must survive encode', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('goose/baseline').buffer)
    const goose: any = Layer(decoded, 'goose').data
    goose.reserved1.simulated = true
    const encoded = await codec.encode(decoded)
    const redecoded: CodecDecodeResult[] = await codec.decode(encoded.packet)
    assert.strictEqual((Layer(redecoded, 'goose').data as any).reserved1.simulated, true)
})

// BUG 1 (REAL): VISIBLE-STRING encode at Goose.ts:995 uses
//   Buffer.from(asciiText,'ascii').toString('hex').padStart(35*2)
// padStart's default fill char is a SPACE. For any string shorter than 35 chars the
// hex is left-padded with spaces, and Buffer.from(<space-prefixed>,'hex') stops at the
// first invalid nibble -> empty buffer. The emitted TLV value is therefore empty.
// Correct behaviour: a short VISIBLE-STRING data item must survive a decode round-trip.
test('BUG1 GOOSE VISIBLE-STRING data item shorter than 35 chars must survive encode', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('goose/baseline').buffer)
    const goose: any = Layer(decoded, 'goose').data
    goose.length = 0
    goose.goosePdu.numDatSetEntries = 1
    goose.goosePdu.allData = [{dataType: 'VISIBLE-STRING', value: 'AnIn1'}]
    const encoded = await codec.encode(decoded)
    const redecoded: CodecDecodeResult[] = await codec.decode(encoded.packet)
    const items: any[] = (Layer(redecoded, 'goose').data as any).goosePdu.allData
    assert.deepStrictEqual(items[0], {dataType: 'VISIBLE-STRING', value: 'AnIn1'})
})

// BUG 2 (REAL): allData TimeStamp loses precision and can emit odd-length bytes.
//   decode Goose.ts:889  parseInt(hex,16).toString()  -> Number, loses >2^53 precision
//   encode Goose.ts:1002 Buffer.from(timestamp.toString(16),'hex') -> no pad to 8 bytes,
//                         odd-length hex is truncated (e.g. value 5 -> '5' -> empty buffer)
// Contrast with the top-level goosePdu.t field (Goose.ts:344/350) which correctly uses
// BigInt + padStart(16,'0'). A full 8-byte TimeStamp must round-trip exactly as a string.
test('BUG2 GOOSE allData TimeStamp must keep 8-byte precision through round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('goose/baseline').buffer)
    const goose: any = Layer(decoded, 'goose').data
    goose.length = 0
    goose.goosePdu.numDatSetEntries = 1
    // Same magnitude as the baseline top-level timestamp; well beyond Number.MAX_SAFE_INTEGER.
    goose.goosePdu.allData = [{dataType: 'TimeStamp', value: '4066394167022397450'}]
    const encoded = await codec.encode(decoded)
    const redecoded: CodecDecodeResult[] = await codec.decode(encoded.packet)
    const items: any[] = (Layer(redecoded, 'goose').data as any).goosePdu.allData
    assert.deepStrictEqual(items[0], {dataType: 'TimeStamp', value: '4066394167022397450'})
})

// BUG 3 (REAL): OCTET-STRING length check mixes units at Goose.ts:985.
//   if (hexText.length > 20)  -> hexText is a HEX string, so length is in hex chars.
// A legal 11..20 byte OCTET-STRING (22..40 hex chars) is wrongly flagged "OCTET-STRING
// too long" even though subarray(0,20) then keeps all bytes (the threshold should be
// the byte length, i.e. Buffer.from(hexText,'hex').length > 20). Here a 12-byte value
// must NOT produce a "too long" error.
test('BUG3 GOOSE 12-byte OCTET-STRING must not be flagged too long', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('goose/baseline').buffer)
    const goose: any = Layer(decoded, 'goose').data
    goose.length = 0
    goose.goosePdu.numDatSetEntries = 1
    goose.goosePdu.allData = [{dataType: 'OCTET-STRING', value: '0102030405060708090a0b0c'}] // 12 bytes
    const encoded = await codec.encode(decoded)
    const tooLong = encoded.errors.filter((e): boolean => e.message.includes('OCTET-STRING too long'))
    assert.strictEqual(tooLong.length, 0, '12-byte OCTET-STRING is within the 20-byte limit and must not be flagged too long')
    // The bytes themselves are preserved (subarray(0,20) keeps 12 bytes) - sanity check.
    const redecoded: CodecDecodeResult[] = await codec.decode(encoded.packet)
    const items: any[] = (Layer(redecoded, 'goose').data as any).goosePdu.allData
    assert.strictEqual(items[0].value, '0102030405060708090a0b0c')
})

// BUG 4 (REAL): reserved1.reserved encode uses bitLength 16 where it should be 15
// (Goose.ts:195, writeBits(4,2,1,16,value)). The reserved1 word is 16 bits: bit0 =
// Simulated, bits 1..15 = reserved (15 bits). writeBits pads the value to 16 bits and
// writes its HIGH 15 bits into positions 1..15, i.e. it drops the LSB (value >> 1):
// 0x7FFF is written as 0x3FFF, and 0x0001 is written as 0x0000 (verified in isolation).
// NOTE: the symptom is additionally masked by the already-known reserved2-offset bug -
// reserved2 encode also writes byte offset 4 (should be 6) and overwrites the whole
// word last - so reserved1.reserved cannot survive a round-trip either way. Correct
// behaviour: a reserved1.reserved value set by the caller must survive encode.
test('BUG4 GOOSE reserved1.reserved must survive encode without dropping its low bit', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('goose/baseline').buffer)
    const goose: any = Layer(decoded, 'goose').data
    goose.reserved1.reserved = 0x7FFF
    const encoded = await codec.encode(decoded)
    const redecoded: CodecDecodeResult[] = await codec.decode(encoded.packet)
    assert.strictEqual((Layer(redecoded, 'goose').data as any).reserved1.reserved, 0x7FFF)
})
