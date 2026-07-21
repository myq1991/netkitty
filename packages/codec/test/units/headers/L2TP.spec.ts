import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// L2TP v2 control message SCCRQ (RFC 2661) on UDP 1701: the flag-conditional header (T/L/S set,
// version 2) plus a list of AVPs. Byte-perfect through the master parse.
test('L2TP control SCCRQ: flag-conditional header + AVP list + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('l2tp/control-sccrq').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'l2tp'])
    const l2tp: any = Layer(decoded, 'l2tp').data
    assert.strictEqual(l2tp.flags.type, true, 'control message')
    assert.strictEqual(l2tp.flags.length, true, 'length present')
    assert.strictEqual(l2tp.flags.sequence, true, 'sequence present')
    assert.strictEqual(l2tp.flags.version, 2, 'L2TPv2')
    assert.strictEqual(l2tp.length, 56)
    assert.strictEqual(l2tp.tunnelId, 0)
    assert.strictEqual(l2tp.sessionId, 0)
    assert.strictEqual(l2tp.avps.length, 5, 'five AVPs')
    // First AVP is Message Type = SCCRQ (1).
    assert.strictEqual(l2tp.avps[0].attrType, 0, 'Message Type AVP')
    assert.strictEqual(l2tp.avps[0].value, '0001', 'SCCRQ')
    assert.strictEqual(l2tp.avps[0].mandatory, true)
    // Host Name AVP carries "lac1".
    const hostName: any = l2tp.avps.find((a: any): boolean => a.attrType === 7)
    assert.strictEqual(Buffer.from(hostName.value, 'hex').toString('latin1'), 'lac1')
})

// A data message (T=0) carries the tunneled PPP payload, not AVPs. The codec keeps it as raw hex and
// must not try to parse AVPs out of it.
test('L2TP data message keeps its tunneled payload verbatim (no AVP mis-parse)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 1701, dstport: 1701}},
        {id: 'l2tp', data: {
            flags: {type: false, length: false, sequence: false, offset: false, priority: false, version: 2},
            tunnelId: 1, sessionId: 2, payload: 'ff03c021deadbeef' // a PPP LCP-ish frame
        }}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'l2tp'])
    const l2tp: any = Layer(decoded, 'l2tp').data
    assert.strictEqual(l2tp.flags.type, false, 'data message')
    assert.strictEqual(l2tp.tunnelId, 1)
    assert.strictEqual(l2tp.sessionId, 2)
    assert.strictEqual(l2tp.payload, 'ff03c021deadbeef', 'tunneled payload preserved verbatim')
    assert.ok(!l2tp.avps || l2tp.avps.length === 0, 'no AVPs parsed from a data message')
})

// Crafting: build a control message with the L flag set but no explicit length — the codec auto-computes
// the L2TP Length (whole message from the flags byte). Verify it lands correctly.
test('L2TP faithfully encodes a crafted control message and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 1701, dstport: 1701}},
        {id: 'l2tp', data: {
            flags: {type: true, length: true, sequence: true, offset: false, priority: false, version: 2},
            tunnelId: 5, sessionId: 0, ns: 1, nr: 2,
            avps: [{mandatory: true, hidden: false, vendorId: 0, attrType: 0, value: '0006'}] // Message Type = SLI-ish
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'l2tp'])
    const l2tp: any = Layer(decoded, 'l2tp').data
    assert.strictEqual(l2tp.tunnelId, 5)
    assert.strictEqual(l2tp.ns, 1)
    assert.strictEqual(l2tp.nr, 2)
    // header = flags(2)+length(2)+tunnel(2)+session(2)+Ns(2)+Nr(2)=12, plus one 8-byte AVP = 20.
    assert.strictEqual(l2tp.length, 20, 'auto-computed L2TP Length')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Reserved bits (both the header flag reserved bits and the AVP reserved bits) are captured verbatim,
// so even a non-conformant frame that sets them round-trips byte-for-byte (matching the RMCP precedent).
test('L2TP preserves reserved flag/AVP bits for a byte-perfect round-trip', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 1701, dstport: 1701}},
        {id: 'l2tp', data: {
            flags: {type: true, length: true, sequence: true, offset: false, priority: false, version: 2,
                reserved1: 3, reserved2: 1, reserved3: 15},
            tunnelId: 1, sessionId: 0, ns: 0, nr: 0,
            avps: [{mandatory: true, hidden: false, reserved: 5, vendorId: 0, attrType: 0, value: '0001'}]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const l2tp: any = Layer(decoded, 'l2tp').data
    assert.strictEqual(l2tp.flags.reserved1, 3, 'header reserved bits 2-3 preserved')
    assert.strictEqual(l2tp.flags.reserved2, 1, 'header reserved bit 5 preserved')
    assert.strictEqual(l2tp.flags.reserved3, 15, 'header reserved bits 8-11 preserved')
    assert.strictEqual(l2tp.avps[0].reserved, 5, 'AVP reserved bits preserved')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

test('L2TP truncated mid-AVP: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('l2tp/control-sccrq').buffer
    await AssertDecodeSurvives(full.subarray(0, 40))
})

// A non-v2 L2TP datagram (version nibble != 2, e.g. L2TPv3) has a different structure and must fall
// through to raw rather than be mis-decoded by the v2 layout.
test('L2TP non-v2 (version nibble != 2) falls through to RawData', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 1701}},
        {id: 'raw', data: {data: 'c8030000000000000000'}} // version nibble 3 (L2TPv3)
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'l2tp'), 'must not claim an L2TPv3 datagram')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw', 'the v3 payload stays raw')
})
