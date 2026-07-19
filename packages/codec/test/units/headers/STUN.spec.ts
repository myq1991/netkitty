import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'

// Real STUN Binding Request (mode: no attributes) captured from turnutils_stunclient → coturn. RFC 5389.
test('STUN binding request: field decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('stun/binding-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'stun'])
    const stun: any = Layer(decoded, 'stun').data
    assert.strictEqual(stun.messageType, 0x0001, 'Binding Request')
    assert.strictEqual(stun.messageLength, 0, 'no attributes')
    assert.strictEqual(stun.magicCookie, '2112a442')
    assert.strictEqual(stun.transactionId, 'c925e106eedd60d36ee2bfa2')
    assert.deepStrictEqual(stun.attributes, [], 'a request carries no attributes')
})

// Real STUN Binding Success Response with four attributes. Exercises the generic TLV path + padding.
test('STUN binding response: attributes decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('stun/binding-response').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'stun'])
    const stun: any = Layer(decoded, 'stun').data
    assert.strictEqual(stun.messageType, 0x0101, 'Binding Success Response')
    assert.strictEqual(stun.messageLength, 60)
    assert.strictEqual(stun.transactionId, 'c925e106eedd60d36ee2bfa2')
    assert.strictEqual(stun.attributes.length, 4)
    // XOR-MAPPED-ADDRESS, MAPPED-ADDRESS, RESPONSE-ORIGIN, SOFTWARE (verbatim TLV values).
    assert.deepStrictEqual(stun.attributes[0], {type: 0x0020, value: '00019a725e12a443'})
    assert.deepStrictEqual(stun.attributes[1], {type: 0x0001, value: '0001bb607f000001'})
    assert.deepStrictEqual(stun.attributes[2], {type: 0x802b, value: '00010d967f000001'})
    assert.deepStrictEqual(stun.attributes[3], {type: 0x8022, value: '436f7475726e2d342e362e312027476f72737427'})
})

// Negative / crafting: encode is a faithful executor. Craft a Binding Indication (0x0011) with a
// reserved attribute type carrying a value whose length (2) forces 2 bytes of padding — the length
// and padding are regenerated, and the whole packet survives a byte round-trip. messageLength is left
// 0 so it auto-computes from the attributes (2 attrs × 4 header + 4/4 value+pad = 8 + 8 = 16... below).
test('STUN faithfully encodes a crafted indication with a reserved attribute needing padding', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 50000, dstport: 3478}},
        {id: 'stun', data: {
            messageType: 0x0011, messageLength: 0, magicCookie: '2112a442',
            transactionId: 'aabbccddeeff00112233445566',
            attributes: [
                {type: 0x8022, value: '6869'},           // 2-byte value → 2 bytes padding
                {type: 0x0006, value: '0001bb607f000001'} // 8-byte value → no padding
            ]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const stun: any = Layer(decoded, 'stun').data
    assert.strictEqual(stun.messageType, 0x0011)
    // 0x8022: 4 (TLV header) + 2 (value) + 2 (pad) = 8; 0x0006: 4 + 8 = 12; total 20.
    assert.strictEqual(stun.messageLength, 20, 'message length auto-computed from encoded attributes incl. padding')
    assert.strictEqual(stun.attributes.length, 2)
    assert.deepStrictEqual(stun.attributes[0], {type: 0x8022, value: '6869'}, 'value survives, padding stripped on re-decode')
    assert.deepStrictEqual(stun.attributes[1], {type: 0x0006, value: '0001bb607f000001'})
})

// RFC 5389 §15: attribute padding MAY be any value. A frame whose padding is non-zero must still
// round-trip byte-for-byte — the actual padding bytes are preserved per attribute (`pad`), not
// regenerated as zeros. (Regression for critic finding A.)
test('STUN preserves non-zero attribute padding for a byte-perfect round-trip', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 50000, dstport: 3478}},
        {id: 'stun', data: {
            messageType: 0x0001, messageLength: 0, magicCookie: '2112a442',
            transactionId: 'aabbccddeeff00112233445566',
            // 2-byte value → 2 pad bytes; set them non-zero (legal per §15).
            attributes: [{type: 0x8022, value: '6869', pad: 'abcd'}]
        }}
    ])
    // The padding bytes really are on the wire.
    assert.ok(packet.toString('hex').includes('802200026869abcd'), 'type+len+value+non-zero padding present on wire')
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const stun: any = Layer(decoded, 'stun').data
    assert.deepStrictEqual(stun.attributes[0], {type: 0x8022, value: '6869', pad: 'abcd'}, 'non-zero padding is preserved on decode')
    // Re-encoding the decoded tree reproduces the exact same bytes.
    const {packet: reencoded}: {packet: Buffer} = await codec.encode(decoded)
    assert.strictEqual(reencoded.toString('hex'), packet.toString('hex'), 'byte-perfect round-trip with non-zero padding')
})

// A lying Message Length must NOT spawn phantom attributes past the end of the buffer — the loop is
// bounded by the bytes actually present, not just the 16-bit length field. (Regression for finding C.)
test('STUN oversized messageLength does not fabricate attributes past the buffer', async (): Promise<void> => {
    // STUN header only (20 bytes) but claims messageLength 0xFFFF, riding UDP.
    const header: string = '0001ffff2112a442' + 'aabbccddeeff00112233445566'
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 50000, dstport: 3478}},
        {id: 'raw', data: {data: header}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const stun: any = Layer(decoded, 'stun').data
    assert.strictEqual(stun.messageType, 0x0001)
    assert.strictEqual(stun.messageLength, 0xffff, 'the lying length is decoded as-is')
    assert.deepStrictEqual(stun.attributes, [], 'no phantom attributes beyond the 20-byte header')
})

test('STUN truncated mid-attribute: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('stun/binding-response').buffer
    // Cut into the SOFTWARE attribute value (drop the last 10 bytes).
    await AssertDecodeSurvives(full.subarray(0, full.length - 10))
})

// A STUN message on an ephemeral (non-3478) port must still be recognized via its Magic Cookie
// content signature (heuristicFallback), not silently fall to raw.
test('STUN is recognized off its well-known port via the magic cookie', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 55000, dstport: 55001}},
        {id: 'stun', data: {messageType: 0x0001, messageLength: 0, magicCookie: '2112a442', transactionId: 'c925e106eedd60d36ee2bfa2', attributes: []}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'stun'])
})
