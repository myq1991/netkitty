import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Real RADIUS Access-Request (RFC 2865) on UDP 1812 from freeradius radtest. 20-byte header + AVPs.
test('RADIUS access-request: header + AVP decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('radius/access-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'radius'])
    const radius: any = Layer(decoded, 'radius').data
    assert.strictEqual(radius.code, 1, 'Access-Request')
    assert.strictEqual(radius.identifier, 255)
    assert.strictEqual(radius.length, 73)
    assert.strictEqual(radius.authenticator.length, 32, '16-byte authenticator as hex')
    // User-Name(1), User-Password(2), NAS-IP-Address(4), NAS-Port(5), Message-Authenticator(80).
    assert.deepStrictEqual(radius.attributes.map((a: any): number => a.type), [1, 2, 4, 5, 80])
    assert.strictEqual(radius.attributes[0].value, '626f62', 'User-Name = "bob"')
    assert.strictEqual(radius.attributes[2].value, 'ac110003', 'NAS-IP-Address = 172.17.0.3')
})

// Access-Accept with no attributes — the minimal 20-byte RADIUS packet.
test('RADIUS access-accept: bare 20-byte header round-trips', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('radius/access-accept').buffer)
    const radius: any = Layer(decoded, 'radius').data
    assert.strictEqual(radius.code, 2, 'Access-Accept')
    assert.strictEqual(radius.length, 20)
    assert.deepStrictEqual(radius.attributes, [], 'no attributes')
})

// Negative / crafting: build an Accounting-Request with attributes and length 0 (auto-computed).
test('RADIUS faithfully encodes a crafted packet with an auto-computed length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 1813}},
        {id: 'radius', data: {
            code: 4, identifier: 7, authenticator: '00'.repeat(16),
            attributes: [{type: 1, value: '616c696365'}, {type: 40, value: '00000001'}]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const radius: any = Layer(decoded, 'radius').data
    assert.strictEqual(radius.code, 4, 'Accounting-Request')
    // 20 header + (2+5) User-Name + (2+4) Acct-Status-Type = 20 + 7 + 6 = 33.
    assert.strictEqual(radius.length, 33, 'length auto-computed from header + attributes')
    assert.deepStrictEqual(radius.attributes, [{type: 1, value: '616c696365'}, {type: 40, value: '00000001'}])
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

test('RADIUS truncated mid-attribute: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('radius/access-request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 8))
})

// A sub-20-byte payload on a RADIUS port is not RADIUS: it must fall through to raw, not an under-length layer.
test('RADIUS does not claim a sub-20-byte payload', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 1812}},
        {id: 'raw', data: {data: '0101000a00'}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'raw'])
})

// match() must bound by the UDP PAYLOAD length, not the captured frame: a 19-byte payload with an
// Ethernet trailer after it must fall through to raw (not over-read the trailer into the header).
// (Regression for a critic finding.) The trailer is appended by hand-building the frame.
test('RADIUS does not claim a padded sub-20-byte payload (bounds by UDP payload, not frame)', async (): Promise<void> => {
    // eth(14)+ipv4(20)+udp(8)=42 header, then a 19-byte UDP payload, then a 3-byte Ethernet trailer.
    const built: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 1812, length: 27}}, // 8 header + 19 payload
        {id: 'raw', data: {data: 'aa'.repeat(19)}}
    ])
    const withTrailer: Buffer = Buffer.concat([built.packet, Buffer.from('bbccdd', 'hex')])
    const decoded: CodecDecodeResult[] = await codec.decode(withTrailer)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'radius'), 'a 19-byte UDP payload is not RADIUS even with a trailer')
})

// A decoded on-wire Length of 0x0000 (malformed — RFC mandates >= 20) must round-trip verbatim, not be
// silently rewritten to an auto-computed length. (Regression for a critic finding.)
test('RADIUS with an on-wire Length of 0 round-trips verbatim', async (): Promise<void> => {
    const built: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 1812}},
        // code=1 id=1 Length=0x0000 authenticator(16 zero) + one AVP type1 len3 val aa
        {id: 'raw', data: {data: '01010000' + '00'.repeat(16) + '0103aa'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(built.packet)
    const radius: any = Layer(decoded, 'radius').data
    assert.strictEqual(radius.length, 0, 'the on-wire Length 0 is decoded as-is')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), built.packet.toString('hex'), 'Length 0 is honored, not auto-computed')
})
