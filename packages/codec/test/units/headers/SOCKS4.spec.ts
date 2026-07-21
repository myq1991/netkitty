import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// A spec-accurate SOCKS4 (protocol version 4) CONNECT request on TCP port 1080: version 4, command 1
// (CONNECT), destination 66.102.7.99:80, userId "Fred". The request is fully structured — version,
// command, dstPort, dstIp and the null-terminated userId — and round-trips byte-for-byte.
test('SOCKS4 request: structured fields + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('socks4/request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'socks4'])
    const socks4: any = Layer(decoded, 'socks4').data
    assert.strictEqual(socks4.messageType, 'request')
    assert.strictEqual(socks4.version, 4)
    assert.strictEqual(socks4.command, 1, 'CONNECT')
    assert.strictEqual(socks4.dstPort, 80)
    assert.strictEqual(socks4.dstIp, '66.102.7.99')
    assert.strictEqual(socks4.userId, 'Fred', 'the null-terminated user-id, kept verbatim')
    assert.strictEqual(socks4.domain, '', 'a plain SOCKS4 request carries no trailing domain')
})

// A server reply (null byte + status 0x5A "request granted" + bound 66.102.7.99:80) is the 8-octet
// reply shape; discriminated from a request by its leading null octet and re-encoded byte-identical.
test('SOCKS4 reply is discriminated by its leading null octet and re-encodes byte-identical', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '66.102.7.99', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 1080, dstport: 51000}},
        {id: 'socks4', data: {messageType: 'reply', version: 0, status: 0x5a, dstPort: 80, dstIp: '66.102.7.99'}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'socks4'])
    const socks4: any = Layer(decoded, 'socks4').data
    assert.strictEqual(socks4.messageType, 'reply', 'a leading null octet marks a reply, not a request')
    assert.strictEqual(socks4.version, 0, 'the reply\'s leading octet is null')
    assert.strictEqual(socks4.status, 0x5a, 'request granted')
    assert.strictEqual(socks4.dstPort, 80)
    assert.strictEqual(socks4.dstIp, '66.102.7.99')
    assert.strictEqual(socks4.userId, '', 'a reply carries no user-id')
})

// SOCKS4a: when the request's dstIp is 0.0.0.x the client appends the unresolved destination host as a
// second null-terminated string after the userId. The codec structures it as `domain`; both the userId
// and domain c-strings honor their terminators, so the SOCKS4a request round-trips byte-for-byte.
test('SOCKS4a request structures the trailing domain and stays byte-perfect', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('socks4/socks4a').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'socks4'])
    const socks4: any = Layer(decoded, 'socks4').data
    assert.strictEqual(socks4.messageType, 'request')
    assert.strictEqual(socks4.dstIp, '0.0.0.1', 'the 0.0.0.x sentinel marking an unresolved host')
    assert.strictEqual(socks4.userId, 'nk')
    assert.strictEqual(socks4.domain, 'www.example.com', 'the trailing domain follows the user-id')
})

// Negative: a payload on port 1080 whose leading octet is neither 0x04 nor 0x00 (here 0x07) must NOT be
// claimed by SOCKS4 — it falls through to raw. And a request truncated mid-userId still decodes without
// throwing and stays re-encodable (best-effort survival).
test('SOCKS4: leading-octet gate rejects non-4/0, and truncation survives', async (): Promise<void> => {
    // 0x07... on port 1080: not a request (0x04) nor a reply (0x00) → must not be claimed.
    const bogus: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 1080}},
        {id: 'raw', data: {data: '0701005042660763'}}
    ])
    const bogusDecoded: CodecDecodeResult[] = await AssertRoundTrip(bogus.packet)
    AssertLayers(bogusDecoded, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!bogusDecoded.some((l: CodecDecodeResult): boolean => l.id === 'socks4'), 'a non-4/0 leading octet must not be claimed as SOCKS4')

    // A request cut mid-message decodes without throwing and remains re-encodable.
    const full: Buffer = LoadPacket('socks4/request').buffer
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 3))
    await codec.encode(survived)
})

// Protocol-specific edge: a BIND request (command 2) with an EMPTY userId — the shortest well-formed
// request is `04 02 <port> <ip> 00` (9 octets: the userId is just its terminator). It round-trips
// byte-for-byte and structures command 2 with an empty userId.
test('SOCKS4: BIND request with empty userId is the 9-octet minimum, byte-perfect', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '203.0.113.9', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 1080}},
        {id: 'socks4', data: {messageType: 'request', command: 2, dstPort: 8080, dstIp: '203.0.113.9', userId: ''}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'socks4'])
    const socks4: any = Layer(decoded, 'socks4').data
    assert.strictEqual(socks4.command, 2, 'BIND')
    assert.strictEqual(socks4.dstPort, 8080)
    assert.strictEqual(socks4.dstIp, '203.0.113.9')
    assert.strictEqual(socks4.userId, '', 'the empty user-id is just its null terminator')
    assert.strictEqual(socks4.domain, '', 'no SOCKS4a domain on a resolved-host request')
})
