import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// RFC 868 Time Protocol (tcp/udp:37) — a 4-byte big-endian seconds-since-1900 server reply.
const SECONDS: number = 0xe7a80c80 // 3886550144

// TCP reply: the 4-byte time value decodes as a single uint32 and round-trips byte-for-byte.
test('TIME over TCP: 4-byte reply + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('time/tcp-response').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'timeproto'])
    assert.strictEqual((Layer(decoded, 'timeproto').data as any).time, SECONDS, 'seconds since 1900-01-01 UTC')
})

// UDP reply: same 4-byte body over UDP/37.
test('TIME over UDP: 4-byte reply + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('time/udp-response').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'timeproto'])
    assert.strictEqual((Layer(decoded, 'timeproto').data as any).time, SECONDS, 'seconds since 1900-01-01 UTC')
})

// Crafting: a reply built from a supplied `time` re-encodes byte-identically, and a high value with the
// top bit set (post-2036 wrap) survives as an unsigned uint32 rather than a negative number.
test('TIME faithfully encodes a crafted reply and preserves the full uint32 range', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.2', dip: '192.0.2.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 37, dstport: 50000}},
        {id: 'timeproto', data: {time: 0xffffffff}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'timeproto'])
    assert.strictEqual((Layer(decoded, 'timeproto').data as any).time, 0xffffffff, 'full uint32 preserved unsigned')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: an empty request (0 payload bytes) on tcp:37 must NOT be claimed as TIME — there is nothing
// to decode and no content signature, so it produces no timeproto layer. A truncated (< 4 byte) reply is
// likewise not claimed and must survive decode without throwing.
test('TIME does not claim an empty request or a truncated reply, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 50000, dstport: 37}}
        // no payload — a bare Time Protocol request
    ])
    const emptyDecoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!emptyDecoded.some((l: CodecDecodeResult): boolean => l.id === 'timeproto'), 'empty request must not be claimed as TIME')

    // A truncated 2-byte reply on tcp:37 — below the 4-byte minimum, so left to raw; must not throw.
    const {packet: truncated}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 37, dstport: 50000}},
        {id: 'raw', data: {data: 'e7a8'}}
    ])
    const truncDecoded: CodecDecodeResult[] = await AssertDecodeSurvives(truncated)
    assert.ok(!truncDecoded.some((l: CodecDecodeResult): boolean => l.id === 'timeproto'), 'truncated (<4B) reply must not be claimed as TIME')
    assert.strictEqual(truncDecoded[truncDecoded.length - 1].id, 'raw', 'truncated payload falls through to raw')
})
