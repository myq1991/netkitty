import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

const PSTR: string = Buffer.from('BitTorrent protocol').toString('hex')

// BitTorrent peer wire (BEP 3) handshake over TCP (dynamic ports) — 68-byte fixed handshake, selected
// by the 0x13 + "BitTorrent protocol" content signature (heuristicFallback), byte-perfect round-trip.
test('BitTorrent handshake: fields + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('bittorrent/handshake').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'bittorrent'])
    const bt: any = Layer(decoded, 'bittorrent').data
    assert.strictEqual(bt.pstrlen, 19, 'pstrlen 0x13')
    assert.strictEqual(bt.pstr, PSTR, '"BitTorrent protocol"')
    assert.strictEqual(bt.reserved, '0000000000100005', 'extension bit-flags')
    assert.strictEqual(bt.infoHash, '0102030405060708090a0b0c0d0e0f1011121314', '20-byte SHA-1 info_hash')
    assert.strictEqual(bt.peerId, Buffer.from('-UT3600-ABCDEFGHIJKL').toString('hex'), '20-byte peer_id')
})

// Crafting: assemble a handshake from scratch on an arbitrary ephemeral port — it is claimed by the
// signature (not a port) and re-encodes byte-identically.
test('BitTorrent faithfully encodes a crafted handshake on an ephemeral port', async (): Promise<void> => {
    const infoHash: string = 'aa'.repeat(20)
    const peerId: string = 'bb'.repeat(20)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 49200, dstport: 55123}},
        {id: 'bittorrent', data: {pstrlen: 19, pstr: PSTR, reserved: '0000000000000000', infoHash: infoHash, peerId: peerId}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'bittorrent'])
    const bt: any = Layer(decoded, 'bittorrent').data
    assert.strictEqual(bt.infoHash, infoHash, 'info_hash round-trips')
    assert.strictEqual(bt.peerId, peerId, 'peer_id round-trips')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// The 68-byte handshake is consumed exactly; a trailing length-prefixed peer message is NOT claimed
// (no signature) and falls through to raw. Both directions round-trip byte-for-byte.
test('BitTorrent bounds the handshake at 68 bytes; a trailing peer message falls through to raw', async (): Promise<void> => {
    const handshake: string = '13' + PSTR + '0000000000100005' + '01'.repeat(20) + '02'.repeat(20)
    const peerMessage: string = '00000001' + '00'                  // len=1, id=0 (choke)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 6881, dstport: 49200}},
        {id: 'raw', data: {data: handshake + peerMessage}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'bittorrent', 'raw'])
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, peerMessage, 'trailing peer message left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a bare length-prefixed peer message (no handshake signature) must NOT be claimed as
// BitTorrent; and a truncated handshake (< 68 bytes) must survive decode without throwing.
test('BitTorrent rejects a non-handshake payload, and truncation survives', async (): Promise<void> => {
    // A peer "interested" message <len=1><id=2> — no 0x13 + "BitTorrent protocol" prefix.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 6881, dstport: 49200}},
        {id: 'raw', data: {data: '0000000102'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'bittorrent'), 'non-handshake payload must not be claimed')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('bittorrent/handshake').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 10))
})
