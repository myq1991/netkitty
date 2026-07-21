import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// LISP control (udp:4342) Map-Request — Type nibble surfaced, whole message kept verbatim, byte-perfect.
test('LISP Map-Request: type + verbatim message + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('lisp/map-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'lisp'])
    const lisp: any = Layer(decoded, 'lisp').data
    assert.strictEqual(lisp.type, 1, 'Map-Request (Type nibble = 1)')
    assert.strictEqual(
        lisp.message,
        '10000001000102030405060700000001c000020100180001c0000200',
        'whole control message kept verbatim (Type octet included)'
    )
})

// Crafting: a Map-Reply (type 2) whose whole message is supplied verbatim must re-encode byte-identically.
test('LISP faithfully encodes a crafted Map-Reply from its verbatim message', async (): Promise<void> => {
    // Map-Reply header (type 2) + record count 1 + 64-bit nonce + one record (EID 192.0.2.0/24, AFI 1).
    const message: string = '20000001' + '1122334455667788' + '00000018000100000001c0000200'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.20', dip: '192.0.2.10', protocol: 17}},
        {id: 'udp', data: {srcport: 4342, dstport: 4342}},
        {id: 'lisp', data: {type: 2, message: message}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'lisp'])
    const lisp: any = Layer(decoded, 'lisp').data
    assert.strictEqual(lisp.type, 2, 'Map-Reply (Type nibble = 2)')
    assert.strictEqual(lisp.message, message, 'message round-trips verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// The message is authoritative and re-emits the Type octet, so a crafted Type nibble that disagrees with
// the message's own first octet does not corrupt the bytes: the message wins and the frame round-trips.
test('LISP message is authoritative over the Type nibble on encode', async (): Promise<void> => {
    const message: string = '80000001aabbccddeeff00110000'          // ECM-style first octet (type 8)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.20', dip: '192.0.2.10', protocol: 17}},
        {id: 'udp', data: {srcport: 4342, dstport: 4342}},
        {id: 'lisp', data: {type: 1, message: message}}    // type says 1, message byte0 says 8
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const lisp: any = Layer(decoded, 'lisp').data
    assert.strictEqual(lisp.type, 8, 'decoded Type comes from the authoritative message byte0 (nibble 8)')
    assert.strictEqual(lisp.message, message, 'message preserved verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/4342 payload shorter than the 4-byte minimum must NOT be claimed as LISP (falls
// through to raw); and a truncated Map-Request must survive decode without throwing.
test('LISP rejects a too-short UDP/4342 payload, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 4342, dstport: 4342}},
        {id: 'raw', data: {data: '100000'}}                // 3 bytes: below the 4-byte match guard
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'lisp'), 'too-short payload must not be claimed as LISP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('lisp/map-request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})
