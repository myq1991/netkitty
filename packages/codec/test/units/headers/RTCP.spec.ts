import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertLayers, Layer} from '../../lib/RoundTrip'
import {Codec} from '../../../src/lib/codec/Codec'
import {RTCP} from '../../../src/lib/codec/headers/RTCP'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// RTCP is not yet wired into the shared PacketHeaders registry, so build a codec with the full built-in
// stack PLUS the RTCP draft appended (the Codec constructor merges custom codecs with the built-ins).
const codec: Codec = new Codec([RTCP])

async function AssertRoundTrip(buffer: Buffer): Promise<CodecDecodeResult[]> {
    const decoded: CodecDecodeResult[] = await codec.decode(buffer)
    const encoded: CodecEncodeResult = await codec.encode(decoded)
    assert.strictEqual(encoded.packet.toString('hex'), buffer.toString('hex'), 'decode→encode must reproduce the original bytes')
    return decoded
}

// RTCP Sender Report (PT=200) over UDP/5005 — 4-byte common header + SSRC + sender info. tshark agrees
// (eth:ethertype:ip:udp:rtcp, rtcp.pt=200). Byte-perfect round-trip.
test('RTCP SR: common header + SSRC + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rtcp/sender-report').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rtcp'])
    const rtcp: any = Layer(decoded, 'rtcp').data
    assert.strictEqual(rtcp.version, 2, 'RTP version 2')
    assert.strictEqual(rtcp.padding, 0, 'no padding')
    assert.strictEqual(rtcp.reportCount, 0, 'zero reception report blocks')
    assert.strictEqual(rtcp.packetType, 200, 'Sender Report')
    assert.strictEqual(rtcp.length, 6, '7 32-bit words minus one')
    assert.strictEqual(rtcp.ssrc, '12345678', 'sender SSRC')
    // Sender info: NTP(8) + RTP ts(4) + packet count(4) + octet count(4) = 20 bytes, bounded by Length.
    assert.strictEqual(rtcp.body, '83aa7e8000000000' + '0e2cba80' + '00000001' + '000000a0')
    assert.strictEqual(rtcp.rest, '', 'single packet — no compound remainder')
})

// Crafting a minimal Receiver Report (PT=201, no report blocks) with the Length auto-derived from the
// (empty) body — first packet is just the 8-byte header+SSRC => Length=1. Must re-encode byte-identically.
test('RTCP faithfully encodes a crafted RR and auto-derives the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 5005, dstport: 5005}},
        {id: 'rtcp', data: {version: 2, padding: 0, reportCount: 0, packetType: 201, ssrc: 'deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rtcp'])
    const rtcp: any = Layer(decoded, 'rtcp').data
    assert.strictEqual(rtcp.packetType, 201, 'Receiver Report')
    assert.strictEqual(rtcp.length, 1, 'auto-derived Length = (8 bytes / 4) - 1 = 1')
    assert.strictEqual(rtcp.body, '', 'empty body')
    assert.strictEqual(rtcp.ssrc, 'deadbeef')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted packet supplies an explicit Length that disagrees with the body
// size — it must be honored verbatim (not overwritten) so a packet carrying any Length round-trips.
test('RTCP honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 5005, dstport: 5005}},
        // body is 4 bytes => honest Length would be 2; supply 2 explicitly to bound the first packet.
        {id: 'rtcp', data: {version: 2, padding: 0, reportCount: 0, packetType: 200, length: 2, ssrc: '11223344', body: 'cafebabe'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const rtcp: any = Layer(decoded, 'rtcp').data
    assert.strictEqual(rtcp.length, 2, 'supplied Length honored')
    assert.strictEqual(rtcp.body, 'cafebabe')
    assert.strictEqual(rtcp.rest, '', 'first packet consumes the whole payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Compound datagram (RFC 3550 §6.1): a Sender Report followed by a BYE. The first packet's body is
// bounded by its Length so it does NOT swallow the BYE; the BYE is captured verbatim in `rest`. Round-trips.
test('RTCP compound: first packet bounded by its Length, trailing packet kept as rest', async (): Promise<void> => {
    const body: string = '83aa7e8000000000' + '0e2cba80' + '00000001' + '000000a0' // SR sender info (20 bytes)
    const bye: string = '81cb0001' + '12345678'                                     // BYE: V2 SC1 PT203 len1 + SSRC
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 5005, dstport: 5005}},
        {id: 'rtcp', data: {version: 2, padding: 0, reportCount: 0, packetType: 200, length: 6, ssrc: '12345678', body: body, rest: bye}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rtcp'])
    const rtcp: any = Layer(decoded, 'rtcp').data
    assert.strictEqual(rtcp.packetType, 200, 'first packet is SR')
    assert.strictEqual(rtcp.body, body, 'SR body bounded by its Length — BYE not swallowed')
    assert.strictEqual(rtcp.rest, bye, 'trailing BYE captured verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: on a bucket port (5005) a payload whose Version is not 2 must NOT be claimed as RTCP (falls
// through to raw); and a valid RTCP packet on a NON-bucket port is not claimed either (strict port-only,
// no heuristicFallback). Truncation must survive decode without throwing.
test('RTCP is strictly port-bucketed and guards Version; junk and truncation survive', async (): Promise<void> => {
    // Version bits = 0 (byte0 0x00) on port 5005 — must not be claimed as RTCP.
    const {packet: badVersion}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 5005, dstport: 5005}},
        {id: 'raw', data: {data: '00c80006aabbccdd00000000'}}
    ])
    const badDecoded: CodecDecodeResult[] = await codec.decode(badVersion)
    assert.ok(!badDecoded.some((l: CodecDecodeResult): boolean => l.id === 'rtcp'), 'version!=2 must not be claimed as RTCP')

    // Valid RTCP bytes but on a non-bucket UDP port (6000) — port-only means it is NOT claimed.
    const {packet: offPort}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 6000, dstport: 6000}},
        {id: 'raw', data: {data: '80c800061234567800000000'}}
    ])
    const offDecoded: CodecDecodeResult[] = await codec.decode(offPort)
    assert.ok(!offDecoded.some((l: CodecDecodeResult): boolean => l.id === 'rtcp'), 'off-bucket port must not be claimed (no heuristicFallback)')

    // Truncated SR must survive decode.
    const full: Buffer = LoadPacket('rtcp/sender-report').buffer
    const truncated: CodecDecodeResult[] = await codec.decode(full.subarray(0, full.length - 5))
    assert.ok(truncated.length > 0, 'decoder must always produce at least one layer')
})
