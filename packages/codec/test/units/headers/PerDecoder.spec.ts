import {test} from 'node:test'
import assert from 'node:assert'
import {PerDecoder, AsnType, AsnTypeTable} from '../../../src/lib/codec/headers/cms/PerDecoder'

// The ALIGNED-PER descriptor interpreter, validated against hand-computed encodings. Each buffer below is
// assembled bit-by-bit from the aligned-PER rules so the decode is checked against a known ground truth.

test('PerDecoder: SEQUENCE of BOOLEAN + constrained INTEGER + VisibleString', (): void => {
    // a(bool)=1, b(int 0..7)=101(=5) -> 1101, pad to octet -> 0xD0; then length 0x02 + "AB".
    const type: AsnType = {k: 'seq', fields: [
        {name: 'a', type: {k: 'bool'}},
        {name: 'b', type: {k: 'int', lb: 0, ub: 7}},
        {name: 'name', type: {k: 'vstr'}}
    ]}
    const out: any = new PerDecoder(Buffer.from([0xd0, 0x02, 0x41, 0x42])).decode(type)
    assert.deepStrictEqual(out, {a: true, b: 5, name: 'AB'})
})

test('PerDecoder: OPTIONAL preamble, ENUMERATED, and SEQUENCE OF', (): void => {
    // preamble bit 0 (flag absent), fc enum(3 values)=01(MX) -> 001, align -> 0x20; SEQUENCE OF len 0x02 + ints 01 02.
    const type: AsnType = {k: 'seq', fields: [
        {name: 'fc', type: {k: 'enum', values: ['ST', 'MX', 'CF']}},
        {name: 'flag', type: {k: 'bool'}, optional: true},
        {name: 'items', type: {k: 'seqof', element: {k: 'int', lb: 0, ub: 255}}}
    ]}
    const out: any = new PerDecoder(Buffer.from([0x20, 0x02, 0x01, 0x02])).decode(type)
    assert.deepStrictEqual(out, {fc: 'MX', items: [1, 2]})
})

test('PerDecoder: DEFAULT-valued absent component takes its default', (): void => {
    // preamble bit 0 (x absent) -> 0, align -> 0x00; x defaults to 7.
    const type: AsnType = {k: 'seq', fields: [
        {name: 'x', type: {k: 'int', lb: 0, ub: 15}, default: 7}
    ]}
    const out: any = new PerDecoder(Buffer.from([0x00])).decode(type)
    assert.deepStrictEqual(out, {x: 7})
})

test('PerDecoder: semi-constrained INTEGER(0..MAX) reads a length determinant then unsigned octets', (): void => {
    // INT32U: length 0x03 then 02 00 00 = 131072 (the real AssociateNegotiate asduSize).
    const out: any = new PerDecoder(Buffer.from([0x03, 0x02, 0x00, 0x00])).decode({k: 'int', lb: 0})
    assert.strictEqual(out, 131072)
})

test('PerDecoder: fully unconstrained INTEGER decodes two\'s-complement (negative and positive)', (): void => {
    assert.strictEqual(new PerDecoder(Buffer.from([0x01, 0xff])).decode({k: 'int'}), -1, 'length 1, 0xff = -1')
    assert.strictEqual(new PerDecoder(Buffer.from([0x01, 0x7f])).decode({k: 'int'}), 127, 'length 1, 0x7f = 127')
    assert.strictEqual(new PerDecoder(Buffer.from([0x02, 0xff, 0x00])).decode({k: 'int'}), -256, 'length 2, 0xff00 = -256')
})

test('PerDecoder: CHOICE and recursive ref through the type table', (): void => {
    // Data ::= CHOICE { i INTEGER(0..15), s VisibleString }. index 1 (s) -> 1, align -> 0x80; len 0x01 + "X".
    const table: AsnTypeTable = {Data: {k: 'choice', alts: [
        {name: 'i', type: {k: 'int', lb: 0, ub: 15}},
        {name: 's', type: {k: 'vstr'}}
    ]}}
    const out: any = new PerDecoder(Buffer.from([0x80, 0x01, 0x58]), table).decode({k: 'ref', name: 'Data'})
    assert.deepStrictEqual(out, {s: 'X'})
})

test('PerDecoder: an extensible SEQUENCE with additions present decodes the root then bails', (): void => {
    // ext bit 1 (additions present), a(bool)=1 -> 11 -> 0xC0. Root decodes; bailed flags the rest for raw fallback.
    const type: AsnType = {k: 'seq', ext: true, fields: [{name: 'a', type: {k: 'bool'}}]}
    const decoder: PerDecoder = new PerDecoder(Buffer.from([0xc0]))
    const out: any = decoder.decode(type)
    assert.deepStrictEqual(out, {a: true}, 'root fields still decode')
    assert.strictEqual(decoder.bailed, true, 'additions-present flags a raw-hex fallback')
})

test('PerDecoder: an unknown ref bails rather than throwing', (): void => {
    const decoder: PerDecoder = new PerDecoder(Buffer.from([0x00]))
    decoder.decode({k: 'ref', name: 'Missing'})
    assert.strictEqual(decoder.bailed, true)
})

test('PerDecoder: a BOOLEAN then an unaligned INTEGER(0..255) decodes both correctly', (): void => {
    // Regression for the range-256 alignment bug: a=true, then b must octet-align. [0x80, 0x55] -> b=85.
    const type: AsnType = {k: 'seq', fields: [
        {name: 'a', type: {k: 'bool'}},
        {name: 'b', type: {k: 'int', lb: 0, ub: 255}}
    ]}
    const out: any = new PerDecoder(Buffer.from([0x80, 0x55])).decode(type)
    assert.deepStrictEqual(out, {a: true, b: 0x55})
})

test('PerDecoder: a fixed 2-char VisibleString after a bit-packed field packs UNALIGNED (<=16-bit exception)', (): void => {
    // flag=true(1 bit), code=VisibleString(SIZE(2))="XX" must NOT octet-align. 1|"XX" -> [0xAC,0x2C,0x00].
    const type: AsnType = {k: 'seq', fields: [
        {name: 'flag', type: {k: 'bool'}},
        {name: 'code', type: {k: 'vstr', min: 2, max: 2}}
    ]}
    const out: any = new PerDecoder(Buffer.from([0xac, 0x2c, 0x00])).decode(type)
    assert.deepStrictEqual(out, {flag: true, code: 'XX'})
})

test('PerDecoder: a fixed 3-char VisibleString (>16 bits) octet-aligns its content', (): void => {
    // flag=true(1 bit), code=VisibleString(SIZE(3))="ABC" aligns -> 0x80, then "ABC".
    const type: AsnType = {k: 'seq', fields: [
        {name: 'flag', type: {k: 'bool'}},
        {name: 'code', type: {k: 'vstr', min: 3, max: 3}}
    ]}
    const out: any = new PerDecoder(Buffer.from([0x80, 0x41, 0x42, 0x43])).decode(type)
    assert.deepStrictEqual(out, {flag: true, code: 'ABC'})
})

test('PerDecoder: a mandatory self-recursive descriptor bails instead of overflowing the stack', (): void => {
    const table: AsnTypeTable = {Rec: {k: 'seq', fields: [{name: 'child', type: {k: 'ref', name: 'Rec'}}]}}
    const decoder: PerDecoder = new PerDecoder(Buffer.from([0x00]), table)
    decoder.decode({k: 'ref', name: 'Rec'}) // must not throw / overflow
    assert.strictEqual(decoder.bailed, true, 'depth guard trips')
})
