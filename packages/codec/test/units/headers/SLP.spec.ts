import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// SLPv2 (udp:427) Service Request — common header (version/function/length/flags/nextExtOffset/xid/
// langTagLen/langTag) + Function-ID-specific body kept verbatim; byte-perfect round-trip.
test('SLP SrvRqst: common header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('slp/srvrqst').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'slp'])
    const slp: any = Layer(decoded, 'slp').data
    assert.strictEqual(slp.version, 2, 'SLPv2')
    assert.strictEqual(slp.functionId, 1, 'SrvRqst')
    assert.strictEqual(slp.length, 54, 'total message length incl 14-byte header + lang tag + body')
    assert.strictEqual(slp.flags, 0, 'no Overflow/Fresh/Multicast flags')
    assert.strictEqual(slp.nextExtOffset, 0, 'no extensions')
    assert.strictEqual(slp.xid, 1, 'transaction id')
    assert.strictEqual(slp.langTagLen, 2, 'lang tag length')
    assert.strictEqual(slp.langTag, '656e', 'lang tag "en"')
    // body: PRList(0) service-type("service:service-agent") scope-list("default") predicate(0) SPI(0)
    assert.strictEqual(slp.body, '00000015736572766963653a736572766963652d6167656e74000764656661756c7400000000', 'SrvRqst body verbatim')
})

// Crafting: a minimal SrvRqst with an empty body and the Length + Language Tag Length auto-computed —
// the message must re-encode byte-identically.
test('SLP faithfully encodes a crafted message and auto-computes Length and Language Tag Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 51000, dstport: 427}},
        // langTag "en" (656e); body empty. Length should derive to 14 + 2 + 0 = 16, langTagLen to 2.
        {id: 'slp', data: {version: 2, functionId: 1, xid: 7, langTag: '656e'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'slp'])
    const slp: any = Layer(decoded, 'slp').data
    assert.strictEqual(slp.functionId, 1, 'SrvRqst')
    assert.strictEqual(slp.length, 16, 'auto-computed Length = 14 header + 2 lang tag + 0 body')
    assert.strictEqual(slp.langTagLen, 2, 'auto-computed Language Tag Length')
    assert.strictEqual(slp.langTag, '656e', 'lang tag "en"')
    assert.strictEqual(slp.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted message supplies an explicit (wrong) Length — it must be honored
// verbatim (not overwritten by the derived value), and the body stays bounded by that Length.
test('SLP honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    // body = one byte 0xff; Length declared as 17 = 14 + 2 (lang tag) + 1 (body).
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 51000, dstport: 427}},
        {id: 'slp', data: {version: 2, functionId: 6, length: 17, xid: 9, langTagLen: 2, langTag: '656e', body: 'ff'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const slp: any = Layer(decoded, 'slp').data
    assert.strictEqual(slp.functionId, 6, 'AttrRqst')
    assert.strictEqual(slp.length, 17, 'supplied Length honored')
    assert.strictEqual(slp.body, 'ff', 'body bounded by the supplied Length')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/427 payload whose Version byte is not 2 must NOT be claimed as SLP (falls through to
// raw); and a truncated SLP message must survive decode without throwing.
test('SLP rejects a non-2 Version on port 427, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 427}},
        // Version byte 0x01 (SLPv1) — not the SLPv2 signature this codec claims.
        {id: 'raw', data: {data: '0101000010000000000000010002656e'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'slp'), 'non-2 Version must not be claimed as SLP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('slp/srvrqst').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 8))
})

// Protocol-specific edge: the body is bounded by the message Length, so trailing bytes after Length are
// left to the codec's recursion / RawData rather than swallowed. Both directions round-trip byte-for-byte.
test('SLP body is bounded by its Length; trailing bytes fall through to raw', async (): Promise<void> => {
    // SLP message: version 2, function 1, langTag "en", body "aabb" => Length = 14 + 2 + 2 = 18 (0x12).
    const message: string = '0201000012' + '0000' + '000000' + '0001' + '0002' + '656e' + 'aabb'
    const trailing: string = 'deadbeef'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 51000, dstport: 427}},
        {id: 'raw', data: {data: message + trailing}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'slp', 'raw'])
    const slp: any = Layer(decoded, 'slp').data
    assert.strictEqual(slp.length, 18, 'declared Length')
    assert.strictEqual(slp.body, 'aabb', 'body bounded by its Length — trailing bytes not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, trailing, 'trailing bytes left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
