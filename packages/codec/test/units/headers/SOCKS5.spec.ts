import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// A spec-accurate SOCKS5 (RFC 1928) client greeting on TCP port 1080: version 5, nMethods 2, methods
// [0x00 no-auth, 0x02 username/password] — the 4 payload bytes `05 02 00 02`. The greeting is fully
// structured and round-trips byte-for-byte.
test('SOCKS5 greeting: structured fields + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('socks5/greeting').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'socks5'])
    const socks5: any = Layer(decoded, 'socks5').data
    assert.strictEqual(socks5.messageType, 'greeting')
    assert.strictEqual(socks5.version, 5)
    assert.strictEqual(socks5.nMethods, 2)
    assert.strictEqual(socks5.methods, '0002', 'the two offered method identifiers, kept verbatim')
    assert.strictEqual(socks5.data, '', 'a greeting carries no verbatim data')
})

// A greeting offering a single method (nMethods 1) re-encodes byte-identical: nMethods exactly bounds the
// methods list, so the whole message is `05 01 00`.
test('SOCKS5 greeting with a different method list re-encodes byte-identical', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 1080}},
        {id: 'socks5', data: {messageType: 'greeting', nMethods: 1, methods: '00'}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'socks5'])
    const socks5: any = Layer(decoded, 'socks5').data
    assert.strictEqual(socks5.messageType, 'greeting')
    assert.strictEqual(socks5.nMethods, 1)
    assert.strictEqual(socks5.methods, '00', 'the single no-auth method')
})

// A non-greeting SOCKS5 message — a client CONNECT request (cmd 1, atyp IPv4 127.0.0.1:80) — is kept
// BYTE-VERBATIM after the version octet as `data`, and round-trips byte-for-byte. Structuring the
// request's conditional address is a later slice.
test('SOCKS5 CONNECT request is kept as verbatim data, byte-perfect', async (): Promise<void> => {
    // Full payload: 05 01 00 01 7f 00 00 01 00 50; data (after the version octet) = 0100017f0000010050.
    const requestData: string = '0100017f0000010050'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 1080}},
        {id: 'socks5', data: {messageType: 'other', version: 5, data: requestData}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'socks5'])
    const socks5: any = Layer(decoded, 'socks5').data
    assert.strictEqual(socks5.messageType, 'other', 'a CONNECT request is not a greeting')
    assert.strictEqual(socks5.version, 5)
    assert.strictEqual(socks5.data, requestData, 'the request is preserved verbatim after the version')
    assert.strictEqual(socks5.methods, '', 'no structured methods for a non-greeting message')
})

// Non-SOCKS5 (version 4) on port 1080 falls to raw; a truncated greeting survives; and SOCKS5 is confined
// to the tcp:1080 bucket — a version-5 payload on another port must NOT be claimed (no heuristicFallback).
test('SOCKS5: version gate, truncation survival, and port confinement', async (): Promise<void> => {
    // A SOCKS4 (version 4) payload on port 1080 must not be claimed by the version-5 gate.
    const v4: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 1080}},
        {id: 'raw', data: {data: '04010050'}}
    ])
    const v4Decoded: CodecDecodeResult[] = await AssertRoundTrip(v4.packet)
    AssertLayers(v4Decoded, ['eth', 'ipv4', 'tcp', 'raw'])

    // A greeting cut mid-message decodes without throwing and stays re-encodable.
    const full: Buffer = LoadPacket('socks5/greeting').buffer
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 1))
    await codec.encode(survived)

    // Port confinement: the same version-5 greeting bytes on port 9999 must fall through to raw.
    const offPort: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 9999}},
        {id: 'raw', data: {data: '05020002'}}
    ])
    const offDecoded: CodecDecodeResult[] = await AssertRoundTrip(offPort.packet)
    AssertLayers(offDecoded, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!offDecoded.some((l: CodecDecodeResult): boolean => l.id === 'socks5'), 'SOCKS5 off port 1080 must not be claimed')
})

// nMethods is honored on encode but never trusted to over-read on decode: a message whose nMethods
// over-claims the bytes actually present (05 05 00 01 — nMethods says 5, only 2 octets follow) is NOT
// mistaken for a greeting. It stays 'other' and is preserved verbatim, so the decoder never reads past the
// captured buffer.
test('SOCKS5: a lying nMethods is not mistaken for a greeting (no over-read)', async (): Promise<void> => {
    // Payload 05 05 00 01: version 5, byte 1 = 0x05 (claims 5 methods) but only 2 further octets exist.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 1080}},
        {id: 'socks5', data: {messageType: 'other', version: 5, data: '050001'}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'socks5'])
    const socks5: any = Layer(decoded, 'socks5').data
    assert.strictEqual(socks5.messageType, 'other', 'an over-claiming nMethods must not read as a greeting')
    assert.strictEqual(socks5.data, '050001', 'bytes preserved verbatim; nMethods never drove an over-read')
    assert.strictEqual(socks5.methods, '', 'no structured methods were fabricated')
})
