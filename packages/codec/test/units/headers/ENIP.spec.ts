import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// EtherNet/IP (tcp:44818) RegisterSession request — 24-byte encapsulation header + 4-byte command data.
// Every multi-byte header field is little-endian.
test('EtherNet/IP RegisterSession: encapsulation header + data + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('enip/register-session').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'enip'])
    const enip: any = Layer(decoded, 'enip').data
    assert.strictEqual(enip.command, 0x0065, 'RegisterSession')
    assert.strictEqual(enip.length, 4, 'data byte count')
    assert.strictEqual(enip.sessionHandle, 0, 'session handle is 0 in a RegisterSession request')
    assert.strictEqual(enip.status, 0, 'success')
    assert.strictEqual(enip.senderContext, '0000000000000000')
    assert.strictEqual(enip.options, 0)
    assert.strictEqual(enip.data, '01000000', 'protocol version 0x0001 (LE) + options flags 0x0000 (LE)')
})

// Crafting: build a SendRRData request (command 0x006f) with the Length auto-computed from the data —
// confirm the little-endian Length lands correctly and the message round-trips byte-for-byte.
test('EtherNet/IP faithfully encodes a crafted request and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 44818}},
        {id: 'enip', data: {
            command: 0x006f, sessionHandle: 0x01020304, status: 0, senderContext: '1122334455667788', options: 0,
            // CPF: interface handle 0, timeout 0, item count 2, null address item, unconnected data item + CIP
            data: '000000000000020000000000b2000600524203200125'
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'enip'])
    const enip: any = Layer(decoded, 'enip').data
    assert.strictEqual(enip.command, 0x006f, 'SendRRData')
    assert.strictEqual(enip.sessionHandle, 0x01020304, 'little-endian session handle')
    assert.strictEqual(enip.senderContext, '1122334455667788')
    // Length = data byte count = 22
    assert.strictEqual(enip.length, 22, 'auto-computed little-endian Length')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A TCP/44818 payload shorter than the 24-byte encapsulation header cannot be EtherNet/IP — it must
// fall through to raw.
test('EtherNet/IP rejects a sub-header payload on port 44818 (falls through to raw)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 44818}},
        {id: 'raw', data: {data: '6500040000000000000000000000000000000000'}} // 20 bytes — one short of the 24-byte header
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'enip'), 'a sub-header payload must not be claimed as EtherNet/IP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
})

test('EtherNet/IP truncated mid-data: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('enip/register-session').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 2))
})
