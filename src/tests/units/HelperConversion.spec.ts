import {test} from 'node:test'
import assert from 'node:assert'
import {BufferToInt16, BufferToInt32, BufferToInt8, BufferToUInt16, BufferToUInt32, BufferToUInt8} from '../../lib/helper/BufferToNumber'
import {BufferToIPv4} from '../../lib/helper/BufferToIP'

// Direct tests for the native Buffer↔number/IP read helpers (previously untested — the codec's
// scalar-field reads all flow through these). Pins full-width, short/truncated, empty, signed, and
// the one deliberate over-wide semantic (big-endian high bytes).
const hex: (s: string) => Buffer = (s: string): Buffer => Buffer.from(s, 'hex')

test('BufferToUInt: full-width big-endian reads', (): void => {
    assert.strictEqual(BufferToUInt8(hex('7f')), 0x7f)
    assert.strictEqual(BufferToUInt16(hex('abcd')), 0xabcd)
    assert.strictEqual(BufferToUInt32(hex('deadbeef')), 0xdeadbeef)
})

test('BufferToInt: full-width signed reads', (): void => {
    assert.strictEqual(BufferToInt8(hex('80')), -128)
    assert.strictEqual(BufferToInt16(hex('ffff')), -1)
    assert.strictEqual(BufferToInt32(hex('ffffffff')), -1)
})

test('BufferToNumber: short/truncated buffers read available low bytes (missing high bytes = 0)', (): void => {
    assert.strictEqual(BufferToUInt16(hex('ab')), 0xab)      // 1 of 2 bytes
    assert.strictEqual(BufferToUInt32(hex('abcd')), 0xabcd)  // 2 of 4 bytes
    // signed falls back to unsigned when under-width (high sign byte absent → non-negative)
    assert.strictEqual(BufferToInt16(hex('ff')), 0xff)
})

test('BufferToNumber: empty buffer reads 0', (): void => {
    assert.strictEqual(BufferToUInt16(hex('')), 0)
    assert.strictEqual(BufferToInt32(hex('')), 0)
})

test('BufferToNumber: over-wide buffer takes big-endian HIGH bytes (deliberate change from old low-byte wrap)', (): void => {
    // 3-byte buffer read as u16: native takes the first (high) 2 octets 0x1234; the old hex path
    // wrapped to the low 2 octets 0x3456. Big-endian is the correct network reading.
    assert.strictEqual(BufferToUInt16(hex('123456')), 0x1234)
    assert.strictEqual(BufferToUInt32(hex('0102030405')), 0x01020304)
})

test('BufferToIPv4: dotted-quad, zero-padded on short buffers', (): void => {
    assert.strictEqual(BufferToIPv4(hex('c0a801fe')), '192.168.1.254')
    assert.strictEqual(BufferToIPv4(hex('0a00')), '10.0.0.0')  // short → missing octets are 0
    assert.strictEqual(BufferToIPv4(hex('')), '0.0.0.0')
})
