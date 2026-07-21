import {test} from 'node:test'
import assert from 'node:assert'
import {PerReader} from '../../../src/lib/codec/headers/cms/PerReader'

// The PER bit-cursor primitives, validated against hand-computed ALIGNED-PER encodings.

test('PerReader.readBits reads MSB-first across octet boundaries', (): void => {
    const r: PerReader = new PerReader(Buffer.from([0xa5, 0x3c])) // 1010 0101 0011 1100
    assert.strictEqual(r.readBits(4), 0xa, 'first nibble')
    assert.strictEqual(r.readBits(4), 0x5, 'second nibble')
    assert.strictEqual(r.readBits(8), 0x3c, 'next octet')
})

test('PerReader.readConstrainedInt packs small ranges as a bit-field with no alignment', (): void => {
    // range 8 (0..7) -> 3 bits. 101 00000 -> 5, then the remaining 5 bits.
    const r: PerReader = new PerReader(Buffer.from([0xa0]))
    assert.strictEqual(r.readConstrainedInt(0, 7), 5, '3-bit constrained int')
    // range 1 -> 0 bits, returns the lower bound
    assert.strictEqual(r.readConstrainedInt(9, 9), 9, 'single-value range consumes no bits')
})

test('PerReader.readConstrainedInt with a non-zero lower bound', (): void => {
    const r: PerReader = new PerReader(Buffer.from([0x60])) // 011 00000
    assert.strictEqual(r.readConstrainedInt(10, 17), 13, 'lb 10 + 3-bit 011 (=3) = 13')
})

test('PerReader.readConstrainedInt: range 256 is a single OCTET-ALIGNED octet, not an unaligned bit-field', (): void => {
    // BOOLEAN true then INTEGER(0..255): the int must octet-align. bit 1 -> pad -> 0x80, then octet 0x55.
    const r: PerReader = new PerReader(Buffer.from([0x80, 0x55]))
    assert.strictEqual(r.readBit(), 1, 'boolean true')
    assert.strictEqual(r.readConstrainedInt(0, 255), 0x55, 'range-256 int octet-aligns to the next byte')
})

test('PerReader.readConstrainedInt: 257..65536 uses two aligned octets', (): void => {
    const r: PerReader = new PerReader(Buffer.from([0x12, 0x34]))
    assert.strictEqual(r.readConstrainedInt(0, 65535), 0x1234, 'two-octet aligned form')
})

test('PerReader.readConstrainedInt: a 32-bit range does not hang and reads the length-prefixed octets', (): void => {
    // range > 65536 (X.691 11.5.7.4): length determinant 0x04 then 4 octets 0x00010f2c (=69420).
    const r: PerReader = new PerReader(Buffer.from([0x04, 0x00, 0x01, 0x0f, 0x2c]))
    assert.strictEqual(r.readConstrainedInt(0, 4294967295), 69420, 'Unsigned32 constrained int, no hang')
})

test('PerReader.readLengthDeterminant: 1-octet and 2-octet forms', (): void => {
    assert.deepStrictEqual(new PerReader(Buffer.from([0x10])).readLengthDeterminant(), {value: 16, fragmented: false}, 'short form 0..127')
    assert.deepStrictEqual(new PerReader(Buffer.from([0x81, 0x00])).readLengthDeterminant(), {value: 256, fragmented: false}, 'long form 128..16383')
    assert.strictEqual(new PerReader(Buffer.from([0xc1, 0x00])).readLengthDeterminant().fragmented, true, 'fragmented form flagged')
})

test('PerReader.readLengthPrefixedString reads an octet-aligned character string', (): void => {
    const r: PerReader = new PerReader(Buffer.from([0x03, 0x41, 0x42, 0x43])) // len 3 + "ABC"
    assert.strictEqual(r.readLengthPrefixedString(), 'ABC', 'length-determinant + aligned content')
})

test('PerReader.align advances to the next octet boundary before octet reads', (): void => {
    const r: PerReader = new PerReader(Buffer.from([0xa0, 0x42])) // 101 00000 | 0x42
    assert.strictEqual(r.readBits(3), 5, '3 bits consumed')
    assert.strictEqual(r.readOctets(1)[0], 0x42, 'readOctets aligns past the partial octet')
})

test('PerReader never throws past the end of the buffer', (): void => {
    const r: PerReader = new PerReader(Buffer.from([0xff]))
    r.readBits(8)
    assert.strictEqual(r.readBits(8), 0, 'reading past the end yields 0')
    assert.strictEqual(r.readLengthPrefixedString(), '', 'string past the end is empty')
    assert.strictEqual(r.readOctets(4).length, 0, 'octets past the end are empty')
    assert.ok(r.bitsRemaining() < 0 || r.bitsRemaining() === 0, 'no bits remain')
})
