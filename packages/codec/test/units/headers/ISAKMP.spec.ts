import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// IKEv2 IKE_SA_INIT (RFC 7296) on UDP 500: the 28-byte fixed header (split version nibbles) plus a
// generic-payload chain SA(33) -> KE(34) -> Nonce(40) -> 0. Byte-perfect through the payload walk.
test('ISAKMP IKEv2 IKE_SA_INIT: fixed header + payload chain + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('isakmp/sa_init').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'isakmp'])
    const isakmp: any = Layer(decoded, 'isakmp').data
    assert.strictEqual(isakmp.version.major, 2, 'IKEv2 (major version nibble 2)')
    assert.strictEqual(isakmp.version.minor, 0)
    assert.strictEqual(isakmp.exchangeType, 34, 'IKE_SA_INIT')
    assert.strictEqual(isakmp.initiatorSPI, '1122334455667788')
    assert.strictEqual(isakmp.responderSPI, '0000000000000000', 'responder SPI zero in an SA_INIT request')
    assert.strictEqual(isakmp.nextPayload, 33, 'first payload is a Security Association')
    assert.strictEqual(isakmp.length, 248)
    assert.strictEqual(isakmp.payloads.length, 3, 'SA, KE, Nonce')
    assert.strictEqual(isakmp.payloads[0].nextPayload, 34, 'SA -> KE')
    assert.strictEqual(isakmp.payloads[1].nextPayload, 40, 'KE -> Nonce')
    assert.strictEqual(isakmp.payloads[2].nextPayload, 0, 'Nonce terminates the chain')
})

// A crafted IKEv1 (version 0x10 -> major 1, minor 0) informational-ish message with an explicit Length
// must re-encode byte-for-byte (the version nibbles and honored Length round-trip exactly).
test('ISAKMP crafted IKEv1 (version 1.0) re-encodes byte-identically', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 500, dstport: 500}},
        {id: 'isakmp', data: {
            initiatorSPI: 'aabbccddeeff0011', responderSPI: '2233445566778899',
            nextPayload: 8, // Hash payload (IKEv1)
            version: {major: 1, minor: 0}, exchangeType: 5, flags: 0x01, messageId: 0x12345678,
            length: 40,
            payloads: [
                {nextPayload: 0, critical: false, reserved: 0, payloadLength: 12, body: 'deadbeef11223344'}
            ]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'isakmp'])
    const isakmp: any = Layer(decoded, 'isakmp').data
    assert.strictEqual(isakmp.version.major, 1, 'IKEv1')
    assert.strictEqual(isakmp.exchangeType, 5)
    assert.strictEqual(isakmp.messageId, 0x12345678)
    assert.strictEqual(isakmp.length, 40, 'explicit Length honored')
    assert.strictEqual(isakmp.payloads[0].body, 'deadbeef11223344')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Crafting with the Length omitted: the codec derives the whole-message Length, the payload-chain walk
// recovers every payload, and it round-trips byte-perfect.
test('ISAKMP length honor-else-derive: auto-computed Length + full chain walk', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 500, dstport: 500}},
        {id: 'isakmp', data: {
            initiatorSPI: '0102030405060708', responderSPI: '1112131415161718',
            nextPayload: 46, // Encrypted payload
            version: {major: 2, minor: 0}, exchangeType: 43, flags: 0x28, messageId: 2,
            // length omitted -> derived
            payloads: [
                {nextPayload: 0, critical: false, reserved: 0, body: 'aabbccddeeff'} // payloadLength derived = 10
            ]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'isakmp'])
    const isakmp: any = Layer(decoded, 'isakmp').data
    // header 28 + one payload (4 generic header + 6 body = 10) = 38
    assert.strictEqual(isakmp.length, 38, 'auto-computed message Length')
    assert.strictEqual(isakmp.payloads.length, 1)
    assert.strictEqual(isakmp.payloads[0].payloadLength, 10, 'derived payload length (4 + 6)')
    assert.strictEqual(isakmp.payloads[0].body, 'aabbccddeeff')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A datagram on UDP 500 whose version nibble is neither 1 nor 2 is not ISAKMP and must fall through to
// raw; and a truncated ISAKMP message must decode without throwing.
test('ISAKMP rejects a bad version nibble on port 500; truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 500}},
        // 28+ bytes with version byte 0x50 (major nibble 5) and a plausible length -> not IKEv1/IKEv2.
        {id: 'raw', data: {data: '11223344556677880000000000000000005022000000000000000020' + '00'.repeat(8)}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'isakmp'), 'must not claim a non-IKE datagram')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw', 'unknown payload stays raw')
    // Truncated real ISAKMP (cut mid-KE payload) must not throw.
    await AssertDecodeSurvives(LoadPacket('isakmp/sa_init').buffer.subarray(0, 90))
})

// A multi-payload chain (SA -> KE -> Cert -> Nonce -> 0) with critical bits and reserved bits set must
// round-trip exactly, proving the nextPayload/payloadLength linking is preserved verbatim.
test('ISAKMP multi-payload chain (critical + reserved bits) round-trips exactly', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.1.1.1', dip: '10.1.1.2', protocol: 17}},
        {id: 'udp', data: {srcport: 500, dstport: 500}},
        {id: 'isakmp', data: {
            initiatorSPI: 'cafebabecafebabe', responderSPI: 'f00df00df00df00d',
            nextPayload: 33, version: {major: 2, minor: 0}, exchangeType: 35, flags: 0x08, messageId: 1,
            payloads: [
                {nextPayload: 34, critical: true,  reserved: 0,  body: '01020304'},          // SA (critical bit set)
                {nextPayload: 37, critical: false, reserved: 5,  body: '0002000011223344'},  // KE (reserved bits set)
                {nextPayload: 40, critical: true,  reserved: 42, body: 'aabb'},              // Cert
                {nextPayload: 0,  critical: false, reserved: 0,  body: 'ffeeddccbbaa99887766'} // Nonce (last)
            ]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'isakmp'])
    const isakmp: any = Layer(decoded, 'isakmp').data
    assert.strictEqual(isakmp.payloads.length, 4, 'all four payloads walked')
    assert.deepStrictEqual(isakmp.payloads.map((p: any): number => p.nextPayload), [34, 37, 40, 0], 'nextPayload linking preserved')
    assert.strictEqual(isakmp.payloads[0].critical, true, 'critical bit preserved')
    assert.strictEqual(isakmp.payloads[1].reserved, 5, 'reserved bits preserved')
    assert.strictEqual(isakmp.payloads[2].critical, true)
    assert.strictEqual(isakmp.payloads[2].reserved, 42)
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
