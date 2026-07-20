import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Kerberos v5 (RFC 4120), UDP/TCP port 88. A message is a BER APPLICATION-tagged element:
// <appTag> <BER length> <body>; the app tag names the type (0x6a AS-REQ … 0x7e KRB-ERROR). Over UDP the
// message is the whole datagram; over TCP a 4-byte BE length prefix precedes it. This slice structures the
// app tag (msgType) + BER length and keeps the body verbatim.

// Real (spec-accurate) AS-REQ over UDP. Fixture was CONSTRUCTED: a hand-built RFC 4120 AS-REQ (pvno 5,
// msg-type 10, a full KDC-REQ-BODY — kdc-options, cname testuser, realm EXAMPLE.COM, sname krbtgt/…,
// till/rtime, nonce, etype list) wrapped in a netkitty eth/ipv4/udp envelope (dst port 88). Verified with
// `tshark -V`: "Protocols in frame: eth:ethertype:ip:udp:kerberos", as-req msg-type krb-as-req (10).
test('Kerberos AS-REQ over UDP: app tag + BER length + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('kerberos/asreq').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'kerberos'])
    const kerberos: any = Layer(decoded, 'kerberos').data
    assert.strictEqual(kerberos.msgType, 0x6a, 'AS-REQ application tag ([APPLICATION 10] = 0x6a = 106)')
    assert.strictEqual(kerberos.recordLength, undefined, 'no TCP record-length prefix over UDP')
    assert.ok(kerberos.body && kerberos.body.length > 0, 'the KDC-REQ body is kept verbatim')
    // The BER length here is long-form (0x6a 81 a2 …): the body is 162 bytes, so the length is 0x81 0xa2.
    assert.strictEqual(kerberos.body.length / 2, 0xa2, 'body length matches the multi-byte BER length (162)')
})

// Crafting: a TGS-REQ (0x6c) over TCP. This is the critical branch — over TCP a 4-byte BE record-length
// prefix precedes the app-tagged message. With recordLength omitted it is auto-derived as the message
// length, and the whole frame must re-encode byte-for-byte (proves the TCP-prefix vs UDP-no-prefix branch).
test('Kerberos TGS-REQ over TCP: 4-byte length prefix auto-derived + byte-perfect re-encode', async (): Promise<void> => {
    const body: string = '30819fa103020105a20302010c' + 'aa'.repeat(140) // small header + filler > 127 bytes
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 55000, dstport: 88}},
        {id: 'kerberos', data: {msgType: 0x6c, body: body}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'kerberos'])
    const kerberos: any = Layer(decoded, 'kerberos').data
    assert.strictEqual(kerberos.msgType, 0x6c, 'TGS-REQ application tag')
    assert.strictEqual(kerberos.body, body, 'the body round-trips verbatim')
    // recordLength = the app-tagged message length: tag(1) + BER length octets + body. A 153-byte body
    // uses a 1-octet long-form length (0x81 0x99 → 2 bytes), so the message is 1 + 2 + 153 = 156.
    const bodyBytes: number = body.length / 2
    const berLenBytes: number = bodyBytes < 0x80 ? 1 : bodyBytes < 0x100 ? 2 : 3
    const messageBytes: number = 1 + berLenBytes + bodyBytes
    assert.strictEqual(kerberos.recordLength, messageBytes, 'TCP record length auto-derived = message length')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A KRB-ERROR (0x7e = [APPLICATION 30]) over UDP round-trips. Confirms the full app-tag set is honored,
// not just requests.
test('Kerberos KRB-ERROR over UDP: 0x7e application tag round-trips', async (): Promise<void> => {
    const body: string = '30783003020105a103020106' + 'bb'.repeat(50)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 60000, dstport: 88}},
        {id: 'kerberos', data: {msgType: 0x7e, body: body}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'kerberos'])
    const kerberos: any = Layer(decoded, 'kerberos').data
    assert.strictEqual(kerberos.msgType, 0x7e, 'KRB-ERROR application tag')
    assert.strictEqual(kerberos.body, body)
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: UDP traffic on port 88 whose first byte is NOT a Kerberos application tag must NOT be claimed
// as Kerberos (port + app-tag signature; no heuristicFallback) — it falls through to raw. And a truncated
// Kerberos message must not throw.
test('Kerberos negative: non-Kerberos on port 88 → raw; truncation survives', async (): Promise<void> => {
    // 0x30 (SEQUENCE) is not a Kerberos application tag — must not match on port 88.
    const notKerberos: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 60000, dstport: 88}},
        {id: 'raw', data: {data: '3003020105ff'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(notKerberos.packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'raw'])
    assert.ok(!decoded.some((layer: CodecDecodeResult): boolean => layer.id === 'kerberos'), 'a non-app-tag byte on 88 is not Kerberos')
    // Truncate the real AS-REQ mid-body: decode must survive without throwing.
    const full: Buffer = LoadPacket('kerberos/asreq').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 20))
})

// The BER length is re-derived in minimal definite form. Craft a body long enough to force a multi-byte
// (long-form) BER length and confirm the app tag + length + body all round-trip byte-for-byte.
test('Kerberos multi-byte BER length: long-form length + app tag round-trip', async (): Promise<void> => {
    const body: string = 'cc'.repeat(300) // 300 bytes → BER length 0x82 0x01 0x2c (long form, 2 length octets)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 60000, dstport: 88}},
        {id: 'kerberos', data: {msgType: 0x6b, body: body}} // AS-REP
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const kerberos: any = Layer(decoded, 'kerberos').data
    assert.strictEqual(kerberos.msgType, 0x6b, 'AS-REP application tag')
    assert.strictEqual(kerberos.body, body, 'a 300-byte body survives the long-form BER length')
    // The encoded message must carry the long-form length 0x6b 82 01 2c. The Kerberos message begins right
    // after eth(14) + ipv4(20, no options) + udp(8) = offset 42.
    const messageStart: number = 42
    assert.strictEqual(packet.subarray(messageStart, messageStart + 4).toString('hex'), '6b82012c', 'long-form BER length 0x82 0x01 0x2c')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
