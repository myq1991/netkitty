import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// A full Hello message (type 0x0100, len 28, msg id 1) with Common Hello Parameters + IPv4 Transport
// Address (1.1.1.1) + Configuration Sequence Number TLVs — 32 bytes on the wire.
const HELLO_MESSAGE: string = '0100001c00000001' + '0400000400' + '0f0000' + '0401000401010101' + '0402000400000001'

// LDP (udp:646) Link Hello — 10-byte common header (version + PDU length + LSR ID + label space) + a Hello
// message carrying three TLVs.
test('LDP Hello: common header + messages + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ldp/hello').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ldp'])
    const ldp: any = Layer(decoded, 'ldp').data
    assert.strictEqual(ldp.version, 1, 'version 1')
    assert.strictEqual(ldp.pduLength, 38, 'PDU length = LSR ID(4) + label space(2) + message(32)')
    assert.strictEqual(ldp.lsrId, '1.1.1.1', 'LSR ID')
    assert.strictEqual(ldp.labelSpace, 0, 'platform-wide label space')
    assert.strictEqual(ldp.messages, '0100001c000000010400000400' + '0f0000' + '0401000401010101' + '0402000400000001', 'Hello message verbatim')
})

// Crafting: a minimal Initialization PDU (type 0x0200) with the PDU Length auto-computed from the LSR ID +
// label space + messages — must re-encode byte-identically.
test('LDP faithfully encodes a crafted Initialization PDU and auto-computes the PDU Length', async (): Promise<void> => {
    // Init message: type 0x0200, message length 20, msg id 1, Common Session Parameters TLV (0x0500 len 14).
    const initMessage: string = '0200' + '0018' + '00000001' + '0500' + '000e' + '0001000f00000000' + '01010101' + '0000'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '1.1.1.1', dip: '2.2.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 646, dstport: 646}},
        {id: 'ldp', data: {version: 1, lsrId: '1.1.1.1', labelSpace: 0, messages: initMessage}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ldp'])
    const ldp: any = Layer(decoded, 'ldp').data
    assert.strictEqual(ldp.pduLength, 6 + initMessage.length / 2, 'auto-computed PDU Length = 6 + message bytes')
    assert.strictEqual(ldp.messages, initMessage, 'Init message verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive PDU Length: a crafted PDU supplies an explicit (lying) PDU Length — it must be honored
// verbatim, and the messages span is bounded by it so no trailing bytes are swallowed.
test('LDP honors an explicitly supplied PDU Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '1.1.1.1', dip: '2.2.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 646, dstport: 646}},
        // PDU Length 38 (0x26) matches the Hello message so the frame is well-formed and round-trips.
        {id: 'ldp', data: {version: 1, pduLength: 38, lsrId: '1.1.1.1', labelSpace: 0, messages: HELLO_MESSAGE}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const ldp: any = Layer(decoded, 'ldp').data
    assert.strictEqual(ldp.pduLength, 38, 'supplied PDU Length honored')
    assert.strictEqual(ldp.messages, HELLO_MESSAGE, 'messages bounded by PDU Length')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/646 payload whose Version is not 1 must NOT be claimed as LDP (falls through to raw);
// and a truncated LDP PDU must survive decode without throwing.
test('LDP rejects a non-1 Version on port 646, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '1.1.1.1', dip: '2.2.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 646}},
        // Version 0x0002 — not the LDP version 1 signature
        {id: 'raw', data: {data: '00020026010101010000' + HELLO_MESSAGE}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'ldp'), 'non-1 Version must not be claimed as LDP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('ldp/hello').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})

// Protocol-specific edge: two LDP PDUs pipelined in one payload. The first PDU is bounded by its PDU
// Length, so its messages do NOT swallow the trailing PDU; the trailing bytes fall through to raw (a leaf
// header advances only over its own PDU). Both directions round-trip byte-for-byte.
test('LDP pipelining: the first PDU is bounded by its PDU Length; the trailing PDU falls through to raw', async (): Promise<void> => {
    const keepalive: string = '0201' + '0004' + '00000002'                 // KeepAlive message (type 0x0201, 8 bytes)
    const firstPdu: string = '0001' + '000e' + '01010101' + '0000' + keepalive   // PDU length 14 = 6 + 8
    const secondPdu: string = '0001' + '000e' + '02020202' + '0000' + '02010004' + '00000003'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '1.1.1.1', dip: '2.2.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 646, dstport: 646}},
        {id: 'raw', data: {data: firstPdu + secondPdu}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ldp', 'raw'])
    const ldp: any = Layer(decoded, 'ldp').data
    assert.strictEqual(ldp.pduLength, 14, 'first PDU length')
    assert.strictEqual(ldp.messages, keepalive, 'messages bounded by PDU Length — trailing PDU not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, secondPdu, 'trailing PDU left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
