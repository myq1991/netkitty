import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// IEEE C37.118.2 command frame (tcp:4712) — the 14-byte common header + body + CHK.
test('C37.118 command frame: common header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('c37118/command').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'c37118'])
    const c: any = Layer(decoded, 'c37118').data
    assert.strictEqual(c.leadIn, 'aa', 'SYNC lead-in 0xAA')
    assert.strictEqual(c.sync.frameType, 4, 'command frame')
    assert.strictEqual(c.sync.version, 1)
    assert.strictEqual(c.framesize, 18)
    assert.strictEqual(c.idcode, 1)
    assert.strictEqual(c.soc, 0x5f000000, 'second of century')
    assert.strictEqual(c.body, '0001', 'command word')
    assert.strictEqual(c.chk, '1551', 'CRC-CCITT honored verbatim')
})

// Crafting: build a config-2 frame (type 3) with a body and confirm the CHK is placed at FRAMESIZE-2.
test('C37.118 faithfully encodes a crafted config-2 frame (body bounded by FRAMESIZE, CHK at the end)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 4712, dstport: 40000}},
        {id: 'c37118', data: {
            leadIn: 'aa', sync: {reserved: 0, frameType: 3, version: 1},
            framesize: 23, idcode: 7, soc: 0x60000000, timeQuality: 0, fractionOfSecond: 0,
            body: '11223344556677', chk: 'abcd' // header 14 + 7-byte body + 2-byte CHK = 23
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'c37118'])
    const c: any = Layer(decoded, 'c37118').data
    assert.strictEqual(c.sync.frameType, 3, 'config-2')
    assert.strictEqual(c.idcode, 7)
    assert.strictEqual(c.body, '11223344556677', 'body preserved verbatim')
    assert.strictEqual(c.chk, 'abcd', 'CHK honored verbatim (a crafted frame may carry any check word)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A TCP/4712 payload without the 0xAA SYNC lead-in must fall through to raw.
test('C37.118 rejects a payload without the 0xAA SYNC lead-in (falls through to raw)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 4712}},
        {id: 'raw', data: {data: 'bb41001200015f00000000000000000001'}} // 0xBB, not 0xAA
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'c37118'), 'must not claim a non-C37.118 payload')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
})

// When FRAMESIZE is omitted from a crafted frame it is derived from the actual body + CHK (14-byte
// header + body + CHK), so the emitted frame is internally consistent.
test('C37.118 auto-computes FRAMESIZE from the body + CHK when omitted', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 4712, dstport: 40000}},
        {id: 'c37118', data: {
            leadIn: 'aa', sync: {reserved: 0, frameType: 4, version: 1},
            idcode: 1, soc: 0, timeQuality: 0, fractionOfSecond: 0, body: '0001', chk: '1551'
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'c37118'])
    // header 14 + body 2 + CHK 2 = 18
    assert.strictEqual((Layer(decoded, 'c37118').data as any).framesize, 18, 'auto-computed FRAMESIZE')
})

test('C37.118 truncated mid-frame: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('c37118/command').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 3))
})
