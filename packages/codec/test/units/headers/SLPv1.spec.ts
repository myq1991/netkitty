import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// SLPv1 — Service Location Protocol Version 1 (RFC 2165) on UDP port 427. It shares the port with SLPv2
// but has a different 12-byte common header, told apart by the Version octet (1 vs 2). The Function-
// specific body is kept verbatim. A real AttrRqst frame must decode its common header and round-trip
// byte-for-byte. (The captured frame's IPv4 checksum was 0 from NIC offload; the fixture carries the
// on-wire-correct checksum so it round-trips — the SLPv1 payload bytes are the real capture.)
test('SLPv1 AttrRqst: common header decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('slp/srvloc-v1-attrrqst').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'slpv1'])
    const slp: any = Layer(decoded, 'slpv1').data
    assert.strictEqual(slp.version, 1, 'Version 1')
    assert.strictEqual(slp.functionId, 6, 'Function AttrRqst (6)')
    assert.strictEqual(slp.length, 44, 'Length spans the whole 44-byte message')
    assert.strictEqual(slp.flags, 0, 'Flags 0')
    assert.strictEqual(slp.dialect, 0, 'Dialect 0')
    assert.strictEqual(slp.languageCode, '656e', 'Language Code "en" kept verbatim as hex')
    assert.strictEqual(slp.charEncoding, 3, 'Character Encoding 3')
    assert.strictEqual(slp.xid, 0x4013, 'XID')
    assert.strictEqual(slp.body, '00000018736572766963653a782d68706e702d646973636f7665723a00000000', 'Function body kept verbatim')
})

// Crafting: a minimal SLPv1 SrvReq on udp:427; the Length is derived from the body when not supplied and
// the message re-encodes byte-identically (the body is opaque hex — a crafted message may carry any bytes).
test('SLPv1 faithfully encodes a crafted SrvReq and derives the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 5000, dstport: 427}},
        {id: 'slpv1', data: {version: 1, functionId: 1, flags: 0, dialect: 0, languageCode: '656e', charEncoding: 3, xid: 0x1234, body: 'deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'slpv1'])
    const slp: any = Layer(decoded, 'slpv1').data
    assert.strictEqual(slp.functionId, 1, 'Function SrvReq (1)')
    assert.strictEqual(slp.length, 16, 'Length auto-derived = 12-byte header + 4-byte body')
    assert.strictEqual(slp.body, 'deadbeef', 'body carried verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Version discriminator: an SLPv2 message on udp:427 (Version 2) must NOT be claimed as SLPv1 — the two
// share the port but are told apart by the Version octet, so the SLPv2 fixture still decodes as slp.
test('SLPv1 does not claim an SLPv2 message (the Version octet discriminates)', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('slp/srvrqst').buffer)
    assert.ok(decoded.some((l: CodecDecodeResult): boolean => l.id === 'slp'), 'SLPv2 frame decodes as slp')
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'slpv1'), 'and is not claimed as slpv1')
})
