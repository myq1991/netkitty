import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// WireGuard Handshake Initiation (message type 1) on UDP/51820: 4-byte prefix (type + 3 zero reserved),
// a little-endian sender index, and the fixed 32/48/28/16/16 crypto-blob layout.
test('WireGuard Handshake Initiation: type-1 layout decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('wireguard/handshake').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'wireguard'])
    const wg: any = Layer(decoded, 'wireguard').data
    assert.strictEqual(wg.messageType, 1, 'Handshake Initiation')
    assert.strictEqual(wg.reserved, '000000', '3 zero reserved bytes')
    assert.strictEqual(wg.sender, 0x3f4a1c05, 'little-endian sender index (wire 05 1c 4a 3f)')
    assert.strictEqual(wg.ephemeral.length / 2, 32, 'ephemeral is 32 bytes')
    assert.strictEqual(wg.static.length / 2, 48, 'encrypted static is 48 bytes')
    assert.strictEqual(wg.timestamp.length / 2, 28, 'encrypted timestamp is 28 bytes')
    assert.strictEqual(wg.mac1.length / 2, 16, 'mac1 is 16 bytes')
    assert.strictEqual(wg.mac2.length / 2, 16, 'mac2 is 16 bytes')
})

// Crafting a Handshake Response (message type 2, 92 bytes): its layout is sender + receiver + ephemeral +
// empty + mac1 + mac2 — a different field set/offset from type 1. Proves the per-type branching and a
// faithful byte-for-byte re-encode.
test('WireGuard faithfully encodes a crafted Handshake Response (type-2 layout)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '02:00:00:00:00:01', smac: '02:00:00:00:00:02', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.9.0.2', dip: '10.9.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 51820, dstport: 51820}},
        {id: 'wireguard', data: {
            messageType: 2, reserved: '000000', sender: 0xa1b2c3d4, receiver: 0x3f4a1c05,
            ephemeral: '11'.repeat(32), empty: '22'.repeat(16), mac1: '33'.repeat(16), mac2: '00'.repeat(16)
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'wireguard'])
    const wg: any = Layer(decoded, 'wireguard').data
    assert.strictEqual(wg.messageType, 2, 'Handshake Response')
    assert.strictEqual(wg.sender, 0xa1b2c3d4, 'little-endian sender index')
    assert.strictEqual(wg.receiver, 0x3f4a1c05, 'little-endian receiver index')
    assert.strictEqual(wg.ephemeral, '11'.repeat(32))
    assert.strictEqual(wg.empty, '22'.repeat(16), 'encrypted empty (16 bytes) — the type-2-only field')
    assert.strictEqual(wg.mac1, '33'.repeat(16))
    // 92-byte payload: 4 (type+reserved) + 4 (sender) + 4 (receiver) + 32 + 16 + 16 + 16
    assert.strictEqual(packet.length - 42, 92, 'type-2 is 92 bytes')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Crafting a Transport Data packet (message type 4): receiver + 64-bit LE counter (kept as an 8-byte HEX
// field to dodge >2^53 precision loss) + the rest-of-datagram encrypted payload. Byte-perfect re-encode.
test('WireGuard faithfully encodes a crafted Transport Data packet with counter + payload', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '02:00:00:00:00:02', smac: '02:00:00:00:00:01', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.9.0.1', dip: '10.9.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 51820, dstport: 51820}},
        {id: 'wireguard', data: {
            messageType: 4, reserved: '000000', receiver: 0x0badf00d,
            // a 64-bit counter beyond 2^53 — HEX keeps every byte exactly (LE nonce 0xfffffffffffffffe)
            counter: 'feffffffffffffff',
            encryptedPacket: 'deadbeefcafebabe0011223344556677'
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'wireguard'])
    const wg: any = Layer(decoded, 'wireguard').data
    assert.strictEqual(wg.messageType, 4, 'Transport Data')
    assert.strictEqual(wg.receiver, 0x0badf00d, 'little-endian receiver index')
    assert.strictEqual(wg.counter, 'feffffffffffffff', '8-byte counter preserved verbatim (no precision loss)')
    assert.strictEqual(wg.encryptedPacket, 'deadbeefcafebabe0011223344556677', 'encrypted payload = rest of datagram')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// The message type + 3 zero reserved bytes is only a weakish 4-byte signature, so a UDP/51820 datagram
// with an out-of-range type (5) or a non-zero reserved byte is NOT WireGuard and must fall through to raw.
test('WireGuard rejects a non-WireGuard UDP/51820 payload (falls through to raw)', async (): Promise<void> => {
    // message type 5 (out of the 1..4 range), otherwise a full 148-byte payload
    const badType: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.9.0.1', dip: '10.9.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 51820, dstport: 51820}},
        {id: 'raw', data: {data: '05000000' + 'ab'.repeat(144)}}
    ])
    const badTypeDecoded: CodecDecodeResult[] = await codec.decode(badType.packet)
    assert.ok(!badTypeDecoded.some((l: CodecDecodeResult): boolean => l.id === 'wireguard'), 'message type 5 is not WireGuard')
    assert.strictEqual(badTypeDecoded[badTypeDecoded.length - 1].id, 'raw')

    // valid type 1 but a non-zero reserved byte breaks the content signature
    const badReserved: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.9.0.1', dip: '10.9.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 51820, dstport: 51820}},
        {id: 'raw', data: {data: '01010000' + 'ab'.repeat(144)}}
    ])
    const badReservedDecoded: CodecDecodeResult[] = await codec.decode(badReserved.packet)
    assert.ok(!badReservedDecoded.some((l: CodecDecodeResult): boolean => l.id === 'wireguard'), 'non-zero reserved is not WireGuard')

    // truncation survives (must not throw, must produce at least one layer)
    const full: Buffer = LoadPacket('wireguard/handshake').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 20))
})

// The sender/receiver indices are LITTLE-ENDIAN: 0x01020304 must land on the wire as 04 03 02 01. This
// pins the hand-written LE codec (and the `>>> 0` unsigned handling).
test('WireGuard sender/receiver indices are little-endian on the wire', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.9.0.1', dip: '10.9.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 51820, dstport: 51820}},
        {id: 'wireguard', data: {
            messageType: 1, reserved: '000000', sender: 0x01020304,
            ephemeral: '00'.repeat(32), static: '00'.repeat(48), timestamp: '00'.repeat(28),
            mac1: '00'.repeat(16), mac2: '00'.repeat(16)
        }}
    ])
    // WireGuard payload starts at eth(14)+ipv4(20)+udp(8) = 42; sender is at payload offset 4 → 46.
    assert.strictEqual(packet.subarray(46, 50).toString('hex'), '04030201', 'sender 0x01020304 → wire 04 03 02 01')
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const wg: any = Layer(decoded, 'wireguard').data
    assert.strictEqual(wg.sender, 0x01020304, 'decodes back to the same unsigned value')
})
