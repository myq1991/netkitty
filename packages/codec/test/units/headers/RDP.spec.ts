import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// RDP X.224 Negotiation Request carried in a COTP Connection Request over TPKT/tcp:3389 — the
// single-packet-identifiable start of every RDP connection. Decodes eth/ip/tcp/tpkt/cotp/rdp.
test('RDP Negotiation Request over COTP CR round-trips byte-perfect', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rdp/negotiation-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tpkt', 'cotp', 'rdp'])
    const rdp: any = Layer(decoded, 'rdp').data
    assert.strictEqual(rdp.negotiationType, 1, 'Negotiation Request (0x01)')
    assert.strictEqual(rdp.flags, 0, 'no flags')
    assert.strictEqual(rdp.length, 8, 'Negotiation length is always 8 (little-endian)')
    assert.strictEqual(rdp.requestedProtocols, 1, 'requested protocol = TLS (0x00000001, little-endian)')
})

// Crafting: a Negotiation Response selecting CredSSP (0x00000002) round-trips byte-identically, exercising
// the little-endian length and protocol fields.
test('RDP faithfully encodes a Negotiation Response (CredSSP) with little-endian fields', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.2', dip: '192.0.2.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 3389, dstport: 50000}},
        {id: 'tpkt', data: {version: 3, reserved: 0}},
        {id: 'cotp', data: {pduType: 0xd0, headerRest: '0000123400'}}, // CC (Connection Confirm)
        {id: 'rdp', data: {negotiationType: 2, flags: 0, length: 8, requestedProtocols: 2}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tpkt', 'cotp', 'rdp'])
    const rdp: any = Layer(decoded, 'rdp').data
    assert.strictEqual(rdp.negotiationType, 2, 'Negotiation Response (0x02)')
    assert.strictEqual(rdp.requestedProtocols, 2, 'selected CredSSP (little-endian 02 00 00 00)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a COTP payload that is not an RDP Negotiation (wrong length field) must NOT be claimed as RDP
// (falls to raw); and a truncated frame survives decode.
test('RDP is not claimed for a non-Negotiation COTP payload; truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 50000, dstport: 3389}},
        {id: 'tpkt', data: {version: 3, reserved: 0}},
        {id: 'cotp', data: {pduType: 0xe0, headerRest: '0000000000'}},
        // type 0x01 but length field 0x0009 (not 8) — not an RDP Negotiation
        {id: 'raw', data: {data: '0100090001000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'rdp'), 'a non-Negotiation payload must not be claimed as RDP')

    await AssertDecodeSurvives(LoadPacket('rdp/negotiation-request').buffer.subarray(0, 24))
})
