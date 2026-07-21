import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Skinny / SCCP (tcp:2000) RegisterReq — 12-byte little-endian header (data length + header version +
// message id) + StationRegisterMessage body. Every multi-byte field is little-endian.
test('Skinny RegisterReq: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('skinny/register').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'skinny'])
    const skinny: any = Layer(decoded, 'skinny').data
    assert.strictEqual(skinny.dataLength, 40, 'little-endian data length = 4-byte messageId + 36-byte body')
    assert.strictEqual(skinny.headerVersion, 0, 'Basic header version')
    assert.strictEqual(skinny.messageId, 0x0001, 'RegisterReq')
    // deviceName "SEP001122334455" (16 bytes) + userId 1 + instance 1 + ip 10.0.0.1 + deviceType 8 + maxStreams 0
    assert.strictEqual(skinny.body, '5345503030313132323333343435350001000000010000000a0000010800000000000000')
})

// Crafting: a KeepAlive (messageId 0x0000, empty body) with the Data Length auto-computed from the
// (empty) body — the minimal well-formed Skinny message must re-encode byte-identically. dataLength = 4
// (the 4-byte messageId, no body).
test('Skinny faithfully encodes a crafted KeepAlive and auto-computes the Data Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 50000, dstport: 2000}},
        {id: 'skinny', data: {headerVersion: 0, messageId: 0x0000}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'skinny'])
    const skinny: any = Layer(decoded, 'skinny').data
    assert.strictEqual(skinny.messageId, 0x0000, 'KeepAlive')
    assert.strictEqual(skinny.dataLength, 4, 'auto-computed Data Length = 4 (messageId only, empty body)')
    assert.strictEqual(skinny.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Data Length: a crafted KeypadButton (messageId 0x0003) supplies an explicit Data
// Length — it must be honored verbatim (not overwritten by the derived value) so a message that carries
// any Data Length round-trips. Also confirms the little-endian messageId lands correctly.
test('Skinny honors an explicitly supplied Data Length (does not derive over it)', async (): Promise<void> => {
    // KeypadButton body: button 5 (LE) => 4 bytes. dataLength = 4 (messageId) + 4 (body) = 8.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.2', dip: '10.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 2000, dstport: 50000}},
        {id: 'skinny', data: {dataLength: 8, headerVersion: 0, messageId: 0x0003, body: '05000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const skinny: any = Layer(decoded, 'skinny').data
    assert.strictEqual(skinny.messageId, 0x0003, 'KeypadButton')
    assert.strictEqual(skinny.dataLength, 8, 'supplied Data Length honored')
    assert.strictEqual(skinny.body, '05000000', 'keypad button 5 (LE)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/2000 payload shorter than the 12-byte header cannot be Skinny — it must fall through
// to raw; and a truncated Skinny message must survive decode without throwing.
test('Skinny rejects a sub-header payload on port 2000, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 50000, dstport: 2000}},
        // 4 bytes — one short of the 12-byte header; no content signature
        {id: 'raw', data: {data: '00000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'skinny'), 'a sub-header payload must not be claimed as Skinny')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('skinny/register').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 5))
})

// Protocol-specific edge: two Skinny messages pipelined in one TCP segment. The first message is bounded
// by its Data Length, so its body does NOT swallow the trailing message; the trailing bytes fall through
// to raw (Skinny is a leaf — nothing demuxes off it, so the codec's recursion finds no Skinny bucket for
// the next layer, matching the length-bounded-TCP-payload precedent). Both directions round-trip.
test('Skinny pipelining: the first message is bounded by its Data Length; the trailing message falls through to raw', async (): Promise<void> => {
    const keepAlive: string = '040000000000000000000000'          // 12-byte KeepAlive (dataLength 4)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 2000, dstport: 50000}},
        {id: 'raw', data: {data: keepAlive + keepAlive}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'skinny', 'raw'])
    const skinny: any = Layer(decoded, 'skinny').data
    assert.strictEqual(skinny.messageId, 0x0000, 'first is KeepAlive')
    assert.strictEqual(skinny.body, '', 'KeepAlive bounded by its Data Length — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, keepAlive, 'trailing KeepAlive left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
