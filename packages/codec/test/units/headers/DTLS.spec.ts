import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// DTLS 1.2 (udp) — 13-byte record header (contentType + version + epoch + sequenceNumber + length) plus a
// ClientHello handshake fragment. Byte-perfect decode→encode.
test('DTLS ClientHello: record header + fragment + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('dtls/clienthello').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'dtls'])
    const dtls: any = Layer(decoded, 'dtls').data
    assert.strictEqual(dtls.contentType, 22, 'handshake content type')
    assert.strictEqual(dtls.version, 'fefd', 'DTLS 1.2')
    assert.strictEqual(dtls.epoch, 0, 'epoch 0')
    assert.strictEqual(dtls.sequenceNumber, '000000000000', '48-bit sequence number')
    assert.strictEqual(dtls.length, 58, 'record length = fragment length')
    assert.strictEqual(
        dtls.fragment,
        '0100002e000000000000002efefd0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000000004002f003501000000',
        'ClientHello handshake fragment, byte-perfect'
    )
})

// Crafting: a change_cipher_spec record (contentType 20, one-byte fragment 0x01) with the Length
// auto-computed from the fragment — the minimal well-formed DTLS record must re-encode byte-identically.
test('DTLS faithfully encodes a crafted change_cipher_spec and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.10', dip: '10.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 50000, dstport: 443}},
        {id: 'dtls', data: {contentType: 20, version: 'fefd', epoch: 1, sequenceNumber: '000000000000', fragment: '01'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'dtls'])
    const dtls: any = Layer(decoded, 'dtls').data
    assert.strictEqual(dtls.contentType, 20, 'change_cipher_spec')
    assert.strictEqual(dtls.length, 1, 'auto-computed Length = 1 (one-byte fragment)')
    assert.strictEqual(dtls.fragment, '01', 'CCS payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted alert supplies an explicit Length — it must be honored verbatim
// (not overwritten by the derived value) so a record that carries any Length round-trips.
test('DTLS honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    // alert record (contentType 21) fragment: level 2 (fatal), description 40 (handshake_failure) = 2 bytes.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.10', protocol: 17}},
        {id: 'udp', data: {srcport: 443, dstport: 50000}},
        {id: 'dtls', data: {contentType: 21, version: 'feff', epoch: 1, sequenceNumber: '0000000000ff', length: 2, fragment: '0228'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const dtls: any = Layer(decoded, 'dtls').data
    assert.strictEqual(dtls.contentType, 21, 'alert')
    assert.strictEqual(dtls.version, 'feff', 'DTLS 1.0')
    assert.strictEqual(dtls.length, 2, 'supplied Length honored')
    assert.strictEqual(dtls.fragment, '0228', 'fatal / handshake_failure')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/443 payload whose first byte is not a DTLS ContentType (20..25), or whose Version is
// not feff/fefd, must NOT be claimed as DTLS (falls through to raw); and a truncated record survives
// decode without throwing.
test('DTLS rejects a non-DTLS UDP/443 payload, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.10', protocol: 17}},
        {id: 'udp', data: {srcport: 50000, dstport: 443}},
        // contentType 22 (a valid DTLS ContentType) but Version 0xfefe — not feff/fefd, so not DTLS
        {id: 'raw', data: {data: '16fefe0000000000000000000affffffffffffffffff'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'dtls'), 'non-DTLS version must not be claimed as DTLS')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('dtls/clienthello').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})

// Protocol-specific edge: a lying Length (declares far more than the datagram carries) must clamp the
// Fragment to the UDP payload rather than reading past it, and must still survive + re-encode.
test('DTLS bounds the Fragment by the UDP payload when the Length lies', async (): Promise<void> => {
    const full: Buffer = LoadPacket('dtls/clienthello').buffer
    const liar: Buffer = Buffer.from(full)
    // record length field: eth(14) + ipv4(20) + udp(8) + 11 = 53
    liar.writeUInt16BE(60000, 53)
    const decoded: CodecDecodeResult[] = await codec.decode(liar)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'dtls'])
    const dtls: any = Layer(decoded, 'dtls').data
    assert.strictEqual(dtls.length, 60000, 'lying Length preserved verbatim')
    assert.strictEqual(dtls.fragment.length / 2, 58, 'Fragment clamped to the actual UDP payload, not the lie')
    // decode must not have thrown, and encode must survive the crafted record
    await codec.encode(decoded)
})
