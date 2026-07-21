import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'
import {RTP} from '../../../src/headers/RTP'
import {Codec} from '../../../src/Codec'

//RTP has no built-in registration (SDP-negotiated dynamic ports); exercise it with a codec that adds RTP
//on top of every built-in, so the default ports 5004/5006/5008 route to it.
const rtpCodec: Codec = new Codec([RTP])

// RTP/AVP over UDP:5004 — 12-byte fixed header (V2, PT=0 PCMU, CC=0, no extension) + 4-byte payload.
test('RTP/AVP: fixed header + payload + byte-perfect round-trip', async (): Promise<void> => {
    const buffer: Buffer = LoadPacket('rtp/avp').buffer
    const decoded: CodecDecodeResult[] = await rtpCodec.decode(buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rtp'])
    const rtp: any = Layer(decoded, 'rtp').data
    assert.strictEqual(rtp.version, 2, 'Version 2')
    assert.strictEqual(rtp.padding, false, 'no padding')
    assert.strictEqual(rtp.extension, false, 'no extension')
    assert.strictEqual(rtp.csrcCount, 0, 'CC=0')
    assert.strictEqual(rtp.marker, false, 'no marker')
    assert.strictEqual(rtp.payloadType, 0, 'PT=0 (PCMU)')
    assert.strictEqual(rtp.sequenceNumber, 1, 'seq 1')
    assert.strictEqual(rtp.timestamp, 8000, 'timestamp 8000')
    assert.strictEqual(rtp.ssrc, 0x12345678, 'SSRC')
    assert.deepStrictEqual(rtp.csrc, [], 'no CSRC identifiers')
    assert.strictEqual(rtp.payload, 'deadbeef', 'media payload verbatim')
    const encoded: CodecEncodeResult = await rtpCodec.encode(decoded)
    assert.strictEqual(encoded.packet.toString('hex'), buffer.toString('hex'), 'byte-perfect round-trip')
})

// Crafting: a minimal RTP packet (CC=0, no extension) with only the fixed header fields — must re-encode
// byte-identically, and the CSRC Count auto-derives to 0 from the (empty) CSRC list.
test('RTP faithfully encodes a crafted minimal packet and derives CSRC Count', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await rtpCodec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 5004, dstport: 5004}},
        {id: 'rtp', data: {version: 2, payloadType: 96, sequenceNumber: 100, timestamp: 160, ssrc: 0xdeadbeef, payload: 'cafe'}}
    ])
    const decoded: CodecDecodeResult[] = await rtpCodec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rtp'])
    const rtp: any = Layer(decoded, 'rtp').data
    assert.strictEqual(rtp.payloadType, 96, 'dynamic PT 96')
    assert.strictEqual(rtp.csrcCount, 0, 'CC derived to 0')
    assert.strictEqual(rtp.ssrc, 0xdeadbeef, 'SSRC round-trips full 32-bit range')
    assert.strictEqual(rtp.payload, 'cafe', 'payload')
    assert.strictEqual((await rtpCodec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// CSRC list + header extension (X=1). CC=2 contributing sources, a header extension with a profile and
// one word of data. The CSRC Count and extension length auto-derive; both directions round-trip.
test('RTP carries CSRC identifiers and a header extension byte-for-byte', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await rtpCodec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 5006, dstport: 5006}},
        {id: 'rtp', data: {
            version: 2, extension: true, marker: true, payloadType: 96,
            sequenceNumber: 7, timestamp: 320, ssrc: 0x11223344,
            csrc: ['aaaaaaaa', 'bbbbbbbb'],
            extensionHeader: {profile: 0xbede, data: '00010203'},
            payload: 'feed'
        }}
    ])
    const decoded: CodecDecodeResult[] = await rtpCodec.decode(packet)
    const rtp: any = Layer(decoded, 'rtp').data
    assert.strictEqual(rtp.extension, true, 'X flag set')
    assert.strictEqual(rtp.marker, true, 'marker set')
    assert.strictEqual(rtp.csrcCount, 2, 'CC derived from CSRC list length')
    assert.deepStrictEqual(rtp.csrc, ['aaaaaaaa', 'bbbbbbbb'], 'CSRC identifiers verbatim')
    assert.strictEqual(rtp.extensionHeader.profile, 0xbede, 'extension profile')
    assert.strictEqual(rtp.extensionHeader.length, 1, 'extension length derived to 1 word')
    assert.strictEqual(rtp.extensionHeader.data, '00010203', 'extension data verbatim')
    assert.strictEqual(rtp.payload, 'feed', 'payload')
    assert.strictEqual((await rtpCodec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/5004 payload whose first 2 bits are not Version 2 must NOT be claimed as RTP (falls
// through to raw); and a truncated RTP packet must survive decode without throwing.
test('RTP rejects a non-version-2 datagram on port 5004, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await rtpCodec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 5004, dstport: 5004}},
        // byte0 = 0x40 → Version 1 (bits 01), not RTP's Version 2
        {id: 'raw', data: {data: '400000010000000000000000'}}
    ])
    const decoded: CodecDecodeResult[] = await rtpCodec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'rtp'), 'version!=2 must not be claimed as RTP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('rtp/avp').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 3))
})

// No over-claim: RTP is registered with port-only matchKeys, so on the default codec the RTP/AVP fixture
// decodes as rtp and nothing else steals UDP/5004.
test('RTP claims its fixture on the default codec (registered on the RTP/AVP port), stolen by no other protocol', async (): Promise<void> => {
    // Registered with port-only matchKeys (udp:5004/5006/5008) and no heuristicFallback, so on the default
    // codec the RTP/AVP fixture (dstport 5004) decodes as rtp — and no other built-in mis-claims it.
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rtp/avp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rtp'])
})

// Regression (was a byte-perfect break): a packet with the X (extension) flag set but fewer than 4
// trailing bytes decodes with no extension header (decode gates on availability) — re-encode must NOT
// synthesize a 4-byte zero extension from the X bit alone. Emitting the extension only when one was
// actually captured keeps decode and encode symmetric.
test('RTP: X=1 with a truncated extension does not synthesize bytes on re-encode', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 5004, dstport: 5004}},
        // V2, X=1, CC=0, then only 2 trailing bytes — not enough for a 4-byte extension header
        {id: 'raw', data: {data: '9000000100001f4012345678aabb'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const rtp: any = Layer(decoded, 'rtp').data
    assert.strictEqual(rtp.extension, true, 'X flag is set')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect, no synthesized extension')
})
