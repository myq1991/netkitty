import {test} from 'node:test'
import assert from 'node:assert'
import {BufferToHex} from '../../lib/helper/BufferToHex'
import {HexToBuffer} from '../../lib/helper/HexToBuffer'
import {IPv4ToBuffer, IPv6ToBuffer} from '../../lib/helper/IPToBuffer'
import {BufferToIPv4, BufferToIPv6} from '../../lib/helper/BufferToIP'
import {Int8ToBERHex} from '../../lib/helper/NumberToBERHex'

test('BufferToHex / HexToBuffer round-trip', (): void => {
    const buffer: Buffer = Buffer.from([0x00, 0x1f, 0xff, 0x80])
    assert.strictEqual(BufferToHex(buffer), '001fff80')
    assert.deepStrictEqual(HexToBuffer('001fff80'), buffer)
})

test('IPv4 address conversion round-trip', (): void => {
    const buffer: Buffer = IPv4ToBuffer('192.168.1.1')
    assert.strictEqual(buffer.length, 4)
    assert.strictEqual(BufferToIPv4(buffer), '192.168.1.1')
})

test('IPv6 full-form address conversion produces 16 bytes', (): void => {
    const buffer: Buffer = IPv6ToBuffer('fe80:0000:0000:0000:d754:0b32:a0b0:3646')
    assert.strictEqual(buffer.length, 16)
    assert.strictEqual(BufferToIPv6(buffer), 'fe80:0000:0000:0000:d754:0b32:a0b0:3646')
})

// KNOWN BUG: ip-address v10 toByteArray() returns the shortest byte array,
// so compressed addresses with leading zero bytes (::1, ::ffff:..., most
// short-form addresses) produce fewer than 16 bytes and get written at the
// wrong position inside packets.
test('IPv6 compressed address (::1) must still produce 16 bytes', (): void => {
    assert.strictEqual(IPv6ToBuffer('::1').length, 16)
})

// KNOWN BUG: signed BER encoding converts to unsigned first and then prepends
// 0x00 whenever the high bit is set - so -1 becomes 0x00ff (= +255 in ASN.1)
// instead of the two's-complement shortest form 0xff.
test('BER encoding of INT8 -1 must be two\'s-complement shortest form (ff)', (): void => {
    assert.strictEqual(Int8ToBERHex(-1), 'ff')
})
