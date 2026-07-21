import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// BSAP-IP (Bristol/Emerson BSAP over UDP, well-known port 1234). No public on-wire byte layout exists,
// so the codec claims the traffic by its well-known port and carries the whole UDP payload verbatim as
// `payload` hex. A frame must round-trip byte-for-byte.
test('BSAP-IP: port-claimed leaf carries the UDP payload verbatim, byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('bsap/basic').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'bsap'])
    const bsap: any = Layer(decoded, 'bsap').data
    assert.strictEqual(bsap.payload, 'aa0100060102030405', 'the whole UDP payload, kept verbatim')
})

// Crafting: a minimal BSAP-IP message on udp:1234 with an arbitrary payload must re-encode byte-identically
// (the payload is opaque hex — a crafted message may carry any bytes).
test('BSAP-IP faithfully encodes a crafted payload on udp:1234', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 1234, dstport: 1234}},
        {id: 'bsap', data: {payload: 'de01ad02be03ef04'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'bsap'])
    const bsap: any = Layer(decoded, 'bsap').data
    assert.strictEqual(bsap.payload, 'de01ad02be03ef04', 'payload carried verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: BSAP-IP is claimed only on udp:1234. The same payload on a different UDP port must NOT be
// claimed as BSAP-IP (falls through to raw); and a message truncated into the payload must survive decode.
test('BSAP-IP rejects other UDP ports, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 5000, dstport: 9999}},
        {id: 'raw', data: {data: 'aa0100060102030405'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'bsap'), 'non-1234 UDP port must not be claimed as BSAP-IP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    // Truncate into the UDP payload (eth/ipv4/udp intact): decode must not throw.
    const full: Buffer = LoadPacket('bsap/basic').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 3))
})

// Edge: an empty UDP payload on port 1234 is NOT claimed as BSAP-IP (the match() payload guard requires
// at least one byte), so a zero-length datagram does not produce a phantom empty layer.
test('BSAP-IP declines an empty UDP payload on port 1234', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 1234, dstport: 1234}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'bsap'), 'empty payload must not be claimed as BSAP-IP')
    AssertLayers(decoded, ['eth', 'ipv4', 'udp'])
})
