import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// AH (RFC 4302) in transport mode over IPv4 (proto 51) protecting an inner UDP datagram. AH is an
// extension-header style shim: its Next Header (17) drives the same `ipproto` demux IPv4 uses, so the
// protected payload recurses into UDP. The 12-byte fixed prefix + 12-byte ICV round-trips byte-for-byte.
test('AH transport over IPv4: fixed prefix + ICV, inner UDP via ipproto demux, byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ah/transport-udp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'ah', 'udp', 'raw'])
    const ah: any = Layer(decoded, 'ah').data
    assert.strictEqual(ah.nxt, 17, 'Next Header = UDP')
    assert.strictEqual(ah.payloadLen, 4, 'Payload Len 4 => 24-byte AH')
    assert.strictEqual(ah.reserved, '0000')
    assert.strictEqual(ah.spi, 0x11223344, 'SPI')
    assert.strictEqual(ah.sequenceNumber, 7, 'Sequence Number')
    assert.strictEqual(ah.icv, 'a1b2c3d4e5f60718293a4b5c', '12-byte HMAC-SHA1-96 ICV')
})

// Crafting: build a transport-mode AH over IPv4 protecting an inner UDP datagram from field values. The
// Next Header (17) recurses into UDP; the whole thing re-encodes byte-identically.
test('AH crafted transport frame protecting inner UDP re-encodes byte-identically', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 51}},
        {id: 'ah', data: {nxt: 17, payloadLen: 4, reserved: '0000', spi: 0xcafebabe, sequenceNumber: 42,
            icv: '0011223344556677889900aa'}},
        {id: 'udp', data: {srcport: 40001, dstport: 40002, checksum: 0x9abc}},
        {id: 'raw', data: {data: 'abcdef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'ah', 'udp', 'raw'])
    const ah: any = Layer(decoded, 'ah').data
    assert.strictEqual(ah.spi, 0xcafebabe)
    assert.strictEqual(ah.sequenceNumber, 42)
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Payload Len is honored-else-derived: omitting it while supplying a 16-byte ICV makes the codec derive
// Payload Len = icvBytes/4 + 1 = 5 (a 28-byte AH), and the derived header round-trips.
test('AH Payload Len is derived from ICV length when omitted (honor-else-derive)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '1.1.1.1', dip: '2.2.2.2', protocol: 51}},
        {id: 'ah', data: {nxt: 4, spi: 1, sequenceNumber: 2, icv: '000102030405060708090a0b0c0d0e0f'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'ah'])
    const ah: any = Layer(decoded, 'ah').data
    assert.strictEqual(ah.payloadLen, 5, 'derived Payload Len for a 16-byte ICV')
    assert.strictEqual(ah.icv, '000102030405060708090a0b0c0d0e0f')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: an IPv4 datagram carrying proto 51 but with fewer than AH's 12-byte fixed prefix must NOT
// be claimed as AH (it falls through to RawData); and a frame truncated mid-AH decodes without throwing.
test('AH does not claim a proto-51 payload shorter than its fixed prefix; truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '1.1.1.1', dip: '2.2.2.2', protocol: 51}},
        {id: 'raw', data: {data: '0102030405'}} // only 5 bytes — below AH's 12-byte minimum
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'ah'), 'sub-prefix proto-51 payload is not AH')
    await AssertDecodeSurvives(LoadPacket('ah/transport-udp').buffer.subarray(0, 40))
})

// Protocol edge: the ICV is honored verbatim (AH cannot rederive an HMAC without the SA key) and a
// non-zero Reserved field is preserved. A next-header of 59 (No-Next-Header) leaves the trailer as Raw.
test('AH honors the ICV and Reserved bytes verbatim; unknown Next Header leaves trailer as raw', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '1.1.1.1', dip: '2.2.2.2', protocol: 51}},
        {id: 'ah', data: {nxt: 59, payloadLen: 2, reserved: 'abcd', spi: 0x0a0b0c0d, sequenceNumber: 99, icv: 'cafebabe'}},
        {id: 'raw', data: {data: '99'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'ah', 'raw'])
    const ah: any = Layer(decoded, 'ah').data
    assert.strictEqual(ah.reserved, 'abcd', 'Reserved honored verbatim, not zeroed')
    assert.strictEqual(ah.icv, 'cafebabe', 'ICV honored verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
