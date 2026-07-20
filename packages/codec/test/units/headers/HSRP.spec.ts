import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// HSRP v1 (RFC 2281, udp:1985) Hello — 20-byte v1 mandatory section, decoded field-by-field, with a
// byte-perfect round-trip over a real-shaped frame (eth/ipv4/udp envelope + HSRP payload).
test('HSRP v1 Hello: full field decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('hsrp/hello').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'hsrp'])
    const hsrp: any = Layer(decoded, 'hsrp').data
    assert.strictEqual(hsrp.version, 0, 'HSRPv1')
    assert.strictEqual(hsrp.opCode, 0, 'Hello')
    assert.strictEqual(hsrp.state, 16, 'Active')
    assert.strictEqual(hsrp.helloTime, 3, 'hellotime 3s')
    assert.strictEqual(hsrp.holdTime, 10, 'holdtime 10s')
    assert.strictEqual(hsrp.priority, 100, 'priority 100')
    assert.strictEqual(hsrp.group, 1, 'group 1')
    assert.strictEqual(hsrp.reserved, 0, 'reserved')
    assert.strictEqual(hsrp.authData, '636973636f000000', 'authentication data "cisco" NUL-padded')
    assert.strictEqual(hsrp.virtualIP, '192.0.2.1', 'virtual IP address')
})

// Crafting: a Coup (op code 1) message with only a few fields supplied — the remaining v1 fields fall to
// their schema defaults (auth all-zero, vip 0.0.0.0). It must decode back to the supplied values and
// re-encode byte-identically (encode is a faithful executor).
test('HSRP faithfully encodes a crafted Coup and round-trips byte-for-byte', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:02', smac: '00:00:0c:07:ac:02', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.20', dip: '224.0.0.2', protocol: 17, ttl: 1}},
        {id: 'udp', data: {srcport: 1985, dstport: 1985}},
        {id: 'hsrp', data: {version: 0, opCode: 1, state: 8, helloTime: 3, holdTime: 10, priority: 120, group: 2, virtualIP: '192.0.2.254'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'hsrp'])
    const hsrp: any = Layer(decoded, 'hsrp').data
    assert.strictEqual(hsrp.opCode, 1, 'Coup')
    assert.strictEqual(hsrp.state, 8, 'Standby')
    assert.strictEqual(hsrp.group, 2, 'group 2')
    assert.strictEqual(hsrp.authData, '0000000000000000', 'default all-zero auth data')
    assert.strictEqual(hsrp.virtualIP, '192.0.2.254', 'supplied virtual IP')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A non-zero Version (HSRPv2 uses a different TLV layout on this port) falls back to a verbatim rawBody
// hex from just after the Version byte, and round-trips byte-for-byte.
test('HSRP with a non-zero version keeps the body verbatim (rawBody fallback)', async (): Promise<void> => {
    const body: string = 'aabbccddeeff00112233445566778899aabbcc' // 19 bytes => 20-byte v2 payload with version
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:66', smac: '00:00:0c:07:ac:03', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.21', dip: '224.0.0.102', protocol: 17, ttl: 1}},
        {id: 'udp', data: {srcport: 1985, dstport: 1985}},
        {id: 'hsrp', data: {version: 2, rawBody: body}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'hsrp'])
    const hsrp: any = Layer(decoded, 'hsrp').data
    assert.strictEqual(hsrp.version, 2, 'HSRPv2 (non-zero version)')
    assert.strictEqual(hsrp.rawBody, body, 'body kept verbatim')
    assert.strictEqual(hsrp.opCode, undefined, 'v1 fields not decoded for a non-zero version')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/1985 datagram shorter than the 20-byte v1 mandatory section must NOT be claimed as
// HSRP (falls through to raw); and a truncated HSRP frame must survive decode without throwing.
test('HSRP rejects a sub-20-byte datagram on port 1985, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:02', smac: '00:00:0c:07:ac:01', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '224.0.0.2', protocol: 17, ttl: 1}},
        {id: 'udp', data: {srcport: 1985, dstport: 1985}},
        {id: 'raw', data: {data: '00001003'}} // only 4 bytes of payload — too short to be HSRP
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'hsrp'), 'sub-20-byte payload must not be claimed as HSRP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('hsrp/hello').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})
