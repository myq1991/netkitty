import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, LayerIds, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// IPsec ESP (RFC 4303) over IPv4 (IP protocol 50). The 8-byte cleartext header (SPI + Sequence Number)
// is surfaced; the encrypted payload is opaque and kept verbatim. Byte-perfect round-trip.
test('ESP over IPv4: SPI + Sequence Number, opaque payload, byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('esp/ipv4').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'esp'])
    const esp: any = Layer(decoded, 'esp').data
    assert.strictEqual(esp.spi, 0x0201a1c2, 'SPI decoded big-endian')
    assert.strictEqual(esp.sequenceNumber, 1, 'Sequence Number')
    assert.strictEqual(esp.encryptedPayload, 'd3a4b7f1092e5c8a1122334455667788aabbccddeeff00112233445566778899aabbccdd', 'payload kept verbatim')
})

// Crafting: build an ESP packet with a high SPI (high bit set → exercises unsigned 32-bit) and a large
// sequence number, then decode and re-encode byte-for-byte.
test('ESP crafted with high SPI/seq (unsigned 32-bit) re-encodes byte-identical', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 50}},
        {id: 'esp', data: {spi: 0xfffe0102, sequenceNumber: 0xdeadbeef, encryptedPayload: 'aabbccddeeff0011'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'esp'])
    const esp: any = Layer(decoded, 'esp').data
    assert.strictEqual(esp.spi, 0xfffe0102, 'high-bit SPI stays unsigned')
    assert.strictEqual(esp.sequenceNumber, 0xdeadbeef, 'high-bit sequence stays unsigned')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Bound edge: the encrypted payload is bounded by the enclosing IP datagram — trailing bytes beyond the
// IP total length (e.g. an Ethernet trailer/padding) must NOT be pulled into encryptedPayload; they fall
// through to RawData, and the whole frame still round-trips.
test('ESP encrypted payload is bounded by the IP datagram (trailing bytes → raw)', async (): Promise<void> => {
    const base: Buffer = LoadPacket('esp/ipv4').buffer
    const framed: Buffer = Buffer.concat([base, Buffer.from('cafe', 'hex')])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(framed)
    AssertLayers(decoded, ['eth', 'ipv4', 'esp', 'raw'])
    const esp: any = Layer(decoded, 'esp').data
    assert.strictEqual(esp.encryptedPayload, 'd3a4b7f1092e5c8a1122334455667788aabbccddeeff00112233445566778899aabbccdd', 'trailing bytes not absorbed')
})

// Negative: IP protocol 50 with fewer than the 8 cleartext bytes must NOT be claimed as ESP (match needs
// the full SPI + Sequence Number in the IP payload) — it falls through to RawData; and a truncated ESP
// packet decodes without throwing.
test('ESP is not claimed on a proto-50 payload shorter than its header; truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 50}},
        {id: 'raw', data: {data: '0201a1c2'}} // only 4 bytes — not enough for SPI + Sequence Number
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!LayerIds(decoded).includes('esp'), 'a 4-byte proto-50 payload must not be mislabeled ESP')
    AssertLayers(decoded, ['eth', 'ipv4', 'raw'])
    const full: Buffer = LoadPacket('esp/ipv4').buffer
    await AssertDecodeSurvives(full.subarray(0, 20))
})

// Protocol-specific edge: ESP over IPv6 (Next Header = 50). Exercises the IPv6 nxt match path and the
// IPv6-payload bound.
test('ESP over IPv6 (Next Header 50): byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('esp/ipv6').buffer)
    AssertLayers(decoded, ['eth', 'ipv6', 'esp'])
    const esp: any = Layer(decoded, 'esp').data
    assert.strictEqual(esp.spi, 0xdeadbeef, 'SPI over IPv6')
    assert.strictEqual(esp.sequenceNumber, 42, 'Sequence Number over IPv6')
    assert.strictEqual(esp.encryptedPayload, '00aabbccddeeff00112233445566778899aabbccddeeff0011', 'IPv6 payload bound')
})
