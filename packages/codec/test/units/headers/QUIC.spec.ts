import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// QUIC v1 (udp:443) Initial — long header (first byte + version + DCID + SCID) plus an opaque
// AEAD-protected body. Byte-perfect decode→encode.
test('QUIC Initial: long header + opaque payload + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('quic/initial').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'quic'])
    const quic: any = Layer(decoded, 'quic').data
    assert.strictEqual(quic.firstByte.headerForm, true, 'long header form')
    assert.strictEqual(quic.firstByte.fixedBit, true, 'fixed bit set')
    assert.strictEqual(quic.firstByte.longPacketType, 0, 'Initial')
    assert.strictEqual(quic.firstByte.typeSpecificBits, 0, 'reserved + packet-number-length bits')
    assert.strictEqual(quic.version, '00000001', 'QUIC v1')
    assert.strictEqual(quic.dcidLength, 8, 'DCID length')
    assert.strictEqual(quic.dcid, '0001020304050607', 'destination connection id')
    assert.strictEqual(quic.scidLength, 4, 'SCID length')
    assert.strictEqual(quic.scid, 'aabbccdd', 'source connection id')
    assert.strictEqual(quic.payload, '00110000000102030405060708090a0b0c0d0e0f', 'opaque encrypted body, verbatim')
    assert.deepStrictEqual(quic.supportedVersions, [], 'not a Version Negotiation packet')
})

// Crafting: a minimal Handshake packet where DCID/SCID lengths are auto-derived from the ID bytes — the
// well-formed long header must re-encode byte-identically.
test('QUIC faithfully encodes a crafted Handshake and derives the connection-ID lengths', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.10', dip: '10.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 50000, dstport: 443}},
        {id: 'quic', data: {
            firstByte: {headerForm: true, fixedBit: true, longPacketType: 2, typeSpecificBits: 0},
            version: '00000001',
            dcid: '0102',
            scid: '0a0b',
            payload: 'ffff'
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'quic'])
    const quic: any = Layer(decoded, 'quic').data
    assert.strictEqual(quic.firstByte.longPacketType, 2, 'Handshake')
    assert.strictEqual(quic.dcidLength, 2, 'auto-derived DCID length')
    assert.strictEqual(quic.scidLength, 2, 'auto-derived SCID length')
    assert.strictEqual(quic.dcid, '0102', 'DCID')
    assert.strictEqual(quic.scid, '0a0b', 'SCID')
    assert.strictEqual(quic.payload, 'ffff', 'opaque body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Version Negotiation (Version == 0, RFC 9000 §17.2.1): the body is an unencrypted list of 4-byte
// Supported Versions, not an opaque payload. Recognized on the well-known QUIC port bucket.
test('QUIC Version Negotiation: decodes the Supported Versions list and round-trips', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.10', protocol: 17}},
        {id: 'udp', data: {srcport: 443, dstport: 50000}},
        {id: 'quic', data: {
            // VN first byte after the Header Form bit is arbitrary (server-chosen) — kept verbatim.
            firstByte: {headerForm: true, fixedBit: false, longPacketType: 0, typeSpecificBits: 5},
            version: '00000000',
            dcid: '0102030405',
            scid: 'aabbccdd',
            supportedVersions: ['00000001', '6b3343cf', 'ff00001d']
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'quic'])
    const quic: any = Layer(decoded, 'quic').data
    assert.strictEqual(quic.version, '00000000', 'Version Negotiation')
    assert.deepStrictEqual(quic.supportedVersions, ['00000001', '6b3343cf', 'ff00001d'], 'offered versions')
    assert.strictEqual(quic.payload, '', 'no opaque payload for VN')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Match discipline: a SHORT header (first byte MSB clear) must NOT be claimed even on udp:443 — its
// first byte is signature-free, so it falls through to raw. And a long-header form with an UNKNOWN
// version off the well-known port must not be heuristically claimed either.
test('QUIC does not over-claim: short headers and unknown-version long headers fall through to raw', async (): Promise<void> => {
    // Short header (0x40: Header Form bit clear) on udp:443 — must be raw, not quic.
    const short: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.10', dip: '10.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 50000, dstport: 443}},
        {id: 'raw', data: {data: '40000102030405060708090a0b0c0d0e0f'}}
    ])
    const shortDecoded: CodecDecodeResult[] = await codec.decode(short.packet)
    assert.ok(!shortDecoded.some((l: CodecDecodeResult): boolean => l.id === 'quic'), 'short header not claimed as QUIC')
    assert.strictEqual(shortDecoded[shortDecoded.length - 1].id, 'raw', 'short header falls through to raw')

    // Long header form (0x80) but an unknown version, off the well-known port — heuristic must not fire.
    const unknown: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.10', dip: '10.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 40001}},
        {id: 'raw', data: {data: 'c012345678080001020304050607000102030405'}}
    ])
    const unknownDecoded: CodecDecodeResult[] = await codec.decode(unknown.packet)
    assert.ok(!unknownDecoded.some((l: CodecDecodeResult): boolean => l.id === 'quic'), 'unknown version off-port not claimed as QUIC')

    // A truncated Initial must survive decode without throwing.
    const full: Buffer = LoadPacket('quic/initial').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 5))
})

// honor-else-derive: a crafted Initial supplies explicit DCID/SCID lengths — they are honored verbatim
// (not overwritten by the derived value) so a packet that carries any length round-trips byte-for-byte.
test('QUIC honors explicitly supplied connection-ID lengths', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.10', dip: '10.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 50000, dstport: 443}},
        {id: 'quic', data: {
            firstByte: {headerForm: true, fixedBit: true, longPacketType: 0, typeSpecificBits: 0},
            version: '00000001',
            dcidLength: 4, dcid: '11223344',
            scidLength: 0, scid: '',
            payload: '0040aa00'
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const quic: any = Layer(decoded, 'quic').data
    assert.strictEqual(quic.dcidLength, 4, 'supplied DCID length honored')
    assert.strictEqual(quic.dcid, '11223344', 'DCID')
    assert.strictEqual(quic.scidLength, 0, 'zero-length SCID honored')
    assert.strictEqual(quic.scid, '', 'empty SCID')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
