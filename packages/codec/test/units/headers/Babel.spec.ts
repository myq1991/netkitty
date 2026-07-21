import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Babel (RFC 8966, udp:6696) — 4-byte header (Magic 42 + Version 2 + Body Length) + a TLV body. The
// fixture carries one Hello TLV (type 4). Byte-perfect round-trip + layered field assertions.
test('Babel Hello: header + TLVs + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('babel/hello').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'babel'])
    const babel: any = Layer(decoded, 'babel').data
    assert.strictEqual(babel.magic, 42, 'Magic == 42')
    assert.strictEqual(babel.version, 2, 'Version == 2')
    assert.strictEqual(babel.bodyLength, 8, 'Body Length = 8 (one 8-byte Hello TLV)')
    assert.strictEqual(babel.tlvs.length, 1, 'one TLV')
    assert.strictEqual(babel.tlvs[0].type, 4, 'Hello')
    assert.strictEqual(babel.tlvs[0].length, 6, 'Hello value byte count')
    assert.strictEqual(babel.tlvs[0].value, '000000020064', 'flags 0, seqno 2, interval 100')
    assert.strictEqual(babel.trailer, '', 'no packet trailer')
})

// Crafting: Pad1 (single byte, no length/value) + PadN + Hello, with the Body Length auto-derived from
// the TLVs. Exercises the Pad1 special case and honor-else-derive Body Length; must re-encode identically.
test('Babel crafts Pad1 + PadN + Hello and auto-derives the Body Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:01:87', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '224.0.0.111', protocol: 17, ttl: 1}},
        {id: 'udp', data: {srcport: 6696, dstport: 6696}},
        {id: 'babel', data: {magic: 42, version: 2, tlvs: [
            {type: 0},                                  // Pad1 — a bare byte
            {type: 1, length: 2, value: '0000'},        // PadN of 2 zero bytes
            {type: 4, length: 6, value: '000000030064'} // Hello, seqno 3
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'babel'])
    const babel: any = Layer(decoded, 'babel').data
    assert.strictEqual(babel.tlvs.length, 3, 'three TLVs')
    assert.strictEqual(babel.tlvs[0].type, 0, 'Pad1')
    assert.strictEqual(babel.tlvs[0].value, undefined, 'Pad1 has no value')
    assert.strictEqual(babel.tlvs[1].type, 1, 'PadN')
    assert.strictEqual(babel.tlvs[2].type, 4, 'Hello')
    // derived Body Length = 1 (Pad1) + (2 + 2) (PadN) + (2 + 6) (Hello) = 13
    assert.strictEqual(babel.bodyLength, 13, 'Body Length auto-derived from the TLVs')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Body Length: an explicitly supplied Body Length that lies (larger than the actual
// body) must be honored verbatim, and the codec must still round-trip byte-for-byte.
test('Babel honors an explicitly supplied Body Length and keeps a packet trailer verbatim', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:01:87', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '224.0.0.111', protocol: 17, ttl: 1}},
        {id: 'udp', data: {srcport: 6696, dstport: 6696}},
        // Body Length 8 (one Hello TLV), then a 2-byte packet trailer (PadN with length 0: type 1, len 0).
        {id: 'babel', data: {magic: 42, version: 2, bodyLength: 8,
            tlvs: [{type: 4, length: 6, value: '000000040064'}], trailer: '0100'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const babel: any = Layer(decoded, 'babel').data
    assert.strictEqual(babel.bodyLength, 8, 'supplied Body Length honored')
    assert.strictEqual(babel.tlvs.length, 1, 'one body TLV (trailer not walked as body)')
    assert.strictEqual(babel.trailer, '0100', 'packet trailer kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/6696 payload whose Magic is not 42 must NOT be claimed as Babel (falls through to
// raw); and a truncated Babel packet must survive decode without throwing.
test('Babel rejects a non-42 Magic on port 6696, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:01:87', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '224.0.0.111', protocol: 17, ttl: 1}},
        {id: 'udp', data: {srcport: 6696, dstport: 6696}},
        // Magic 0x99 (not 42) — not the Babel signature
        {id: 'raw', data: {data: '990200080406000000020064'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'babel'), 'non-42 Magic must not be claimed as Babel')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('babel/hello').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 3))
})

// Protocol-specific edge: a lying Body Length (0xffff, far past the datagram) must be bounded by the UDP
// payload — the TLV walk cannot read past the datagram, the overrunning bytes fall to `trailer`, and
// decode survives and re-encodes.
test('Babel bounds a lying Body Length by the UDP payload', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:01:87', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '224.0.0.111', protocol: 17, ttl: 1}},
        {id: 'udp', data: {srcport: 6696, dstport: 6696}},
        // Magic 42, Version 2, Body Length 0xffff, then a truncated Hello header (type 4, length 0xff)
        {id: 'raw', data: {data: '2a02ffff04ffdeadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'babel'])
    const babel: any = Layer(decoded, 'babel').data
    assert.strictEqual(babel.magic, 42, 'Magic 42 claimed')
    assert.strictEqual(babel.bodyLength, 65535, 'lying Body Length preserved')
    // The Hello header claims length 0xff but only 4 payload bytes remain — the walk stops and the
    // remaining bytes are kept verbatim in the trailer, so nothing is read past the UDP payload.
    assert.strictEqual(babel.trailer, '04ffdeadbeef', 'overrunning bytes kept verbatim, not read past the datagram')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
