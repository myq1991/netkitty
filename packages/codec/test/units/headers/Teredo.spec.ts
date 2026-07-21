import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// A 40-byte inner IPv6 packet (version 6, next header 59 No-Next-Header, hop limit 64) used as the
// tunneled Teredo payload across the crafted cases — Teredo keeps it verbatim as `payload` hex.
const INNER_IPV6: string = '6000000000003b40' + '20010000' + '4136e378' + '800063bf' + '3ffffdd2'
    + 'fe800000' + '00000000' + '00000000' + '00000001'

// Teredo (udp:3544) Origin indication + inner IPv6 — de-obfuscated mapped port/address + payload hex,
// byte-perfect round-trip. tshark dissects the fixture as eth:ethertype:ip:udp:teredo:ipv6.
test('Teredo Origin indication + inner IPv6: fields + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('teredo/origin_ipv6').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'teredo'])
    const teredo: any = Layer(decoded, 'teredo').data
    assert.strictEqual(teredo.authentication, undefined, 'no Authentication indication present')
    assert.strictEqual(teredo.origin.port, 4096, 'mapped port de-obfuscated (0xefff XOR 0xffff)')
    assert.strictEqual(teredo.origin.address, '192.0.2.33', 'mapped address de-obfuscated (0x3ffffdde XOR 0xffffffff)')
    assert.strictEqual(teredo.payload, INNER_IPV6, 'inner IPv6 packet kept verbatim as payload hex')
})

// Crafting: both indication headers (Authentication then Origin) before the inner IPv6. The ID-len /
// AU-len bytes are derived from the client-id / auth-value byte lengths, and the XOR-obfuscated origin
// fields re-encode exactly — a well-formed message round-trips byte-for-byte.
test('Teredo faithfully encodes an Authentication + Origin indication before the inner IPv6', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '66:77:88:99:aa:bb', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '198.51.100.10', dip: '203.0.113.20', protocol: 17}},
        {id: 'udp', data: {srcport: 60000, dstport: 3544}},
        {id: 'teredo', data: {
            authentication: {clientId: '0102', authData: 'aabbcc', nonce: '1122334455667788', confirmation: 0},
            origin: {port: 8080, address: '203.0.113.9'},
            payload: INNER_IPV6
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'teredo'])
    const teredo: any = Layer(decoded, 'teredo').data
    assert.strictEqual(teredo.authentication.clientIdLength, 2, 'ID-len derived from client-id bytes')
    assert.strictEqual(teredo.authentication.authDataLength, 3, 'AU-len derived from auth-value bytes')
    assert.strictEqual(teredo.authentication.clientId, '0102', 'client identifier')
    assert.strictEqual(teredo.authentication.authData, 'aabbcc', 'authentication value')
    assert.strictEqual(teredo.authentication.nonce, '1122334455667788', '8-byte nonce')
    assert.strictEqual(teredo.origin.port, 8080, 'mapped port survives XOR round-trip')
    assert.strictEqual(teredo.origin.address, '203.0.113.9', 'mapped address survives XOR round-trip')
    assert.strictEqual(teredo.payload, INNER_IPV6, 'inner IPv6 payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// No indication header: an inner IPv6 packet (first octet 0x6X, never 0x0000/0x0001) is kept whole as
// payload hex, with no phantom Origin/Authentication objects. Round-trips byte-for-byte.
test('Teredo keeps a bare inner IPv6 payload (no indication header) verbatim', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '66:77:88:99:aa:bb', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '198.51.100.10', dip: '203.0.113.20', protocol: 17}},
        {id: 'udp', data: {srcport: 60000, dstport: 3544}},
        {id: 'teredo', data: {payload: INNER_IPV6}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'teredo'])
    const teredo: any = Layer(decoded, 'teredo').data
    assert.strictEqual(teredo.authentication, undefined, 'no Authentication indication')
    assert.strictEqual(teredo.origin, undefined, 'no Origin indication')
    assert.strictEqual(teredo.payload, INNER_IPV6, 'whole payload kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Robustness: a UDP/3544 payload whose first two octets are 0x0001 but that is too short to hold a full
// Authentication header must NOT be mis-parsed into a (padded) indication — the whole header must fit or
// the bytes stay as payload hex, so it round-trips verbatim. And a truncated frame must survive decode.
test('Teredo does not mis-parse a truncated indication prefix, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '66:77:88:99:aa:bb', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '198.51.100.10', dip: '203.0.113.20', protocol: 17}},
        {id: 'udp', data: {srcport: 60000, dstport: 3544}},
        // 0x0001 = Authentication indicator type, but only 3 bytes total: cannot be a real auth header.
        {id: 'teredo', data: {payload: '000101'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const teredo: any = Layer(decoded, 'teredo').data
    assert.strictEqual(teredo.authentication, undefined, 'truncated prefix not parsed as an indication')
    assert.strictEqual(teredo.payload, '000101', 'kept as payload hex')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')

    const full: Buffer = LoadPacket('teredo/origin_ipv6').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 12))
})
