import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// OPC UA Connection Protocol (OPC UA TCP, IEC 62541-6, tcp:4840) HELLO message. 8-byte frame header
// (MessageType "HEL" + Chunk "F" + LITTLE-ENDIAN uint32 MessageSize) followed by the HELLO body.
// Fixture is CONSTRUCTED (spec-accurate HELLO body in a netkitty-encoded eth/ipv4/tcp envelope).
test('OPC UA HELLO: 8-byte frame header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('opcua/hello').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'opcua'])
    const opcua: any = Layer(decoded, 'opcua').data
    assert.strictEqual(opcua.messageType, 'HEL', 'HELLO message type')
    assert.strictEqual(opcua.chunk, 'F', 'final chunk')
    // MessageSize counts the 8-byte header + 48-byte HELLO body = 56.
    assert.strictEqual(opcua.messageSize, 56, 'MessageSize includes the 8-byte header')
    assert.strictEqual(
        opcua.body,
        '0000000000000100000001000000000000000000180000006f70632e7463703a2f2f6c6f63616c686f73743a34383430',
        'HELLO body: version 0 + rx/tx buffer 65536 + max sizes 0 + endpointUrl len 24 + "opc.tcp://localhost:4840"'
    )
})

// Crafting: a MSG chunk with a 24-byte body → MessageSize 32 (0x20). Confirm MessageSize is LITTLE-ENDIAN
// on the wire (0x20 → bytes 20 00 00 00) and the message re-encodes byte-for-byte.
test('OPC UA MSG: little-endian MessageSize on the wire + byte-perfect re-encode', async (): Promise<void> => {
    const body: string = '112233445566778899aabbccddeeff00112233445566778f' // 24 bytes
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 50000, dstport: 4840}},
        {id: 'opcua', data: {messageType: 'MSG', chunk: 'F', body}}
    ])
    const hex: string = packet.toString('hex')
    // "MSG" + "F" = 4d534746; MessageSize 32 must follow as little-endian bytes 20 00 00 00.
    const idx: number = hex.indexOf('4d534746')
    assert.ok(idx >= 0, 'MSG/F frame header present on the wire')
    assert.strictEqual(hex.substr(idx + 8, 8), '20000000', 'MessageSize 0x20 is little-endian on the wire')
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'opcua'])
    const opcua: any = Layer(decoded, 'opcua').data
    assert.strictEqual(opcua.messageType, 'MSG')
    assert.strictEqual(opcua.messageSize, 32, 'auto-derived MessageSize = 8 header + 24 body')
    assert.strictEqual(opcua.body, body)
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), hex, 'byte-perfect')
})

// MessageSize honor-else-derive, plus pipelining: a MessageSize that bounds the body shorter than the
// captured bytes leaves the trailing bytes to the codec's recursion / RawData.
test('OPC UA MessageSize: honor-else-derive and body bounded by MessageSize (trailing → raw)', async (): Promise<void> => {
    // Derive: no MessageSize supplied → 8 + body bytes.
    const derived: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 50000, dstport: 4840}},
        {id: 'opcua', data: {messageType: 'MSG', chunk: 'F', body: 'aabbccdd'}} // 4 bytes
    ])
    const derivedOpcua: any = Layer(await codec.decode(derived.packet), 'opcua').data
    assert.strictEqual(derivedOpcua.messageSize, 12, 'derived MessageSize = 8 header + 4 body')

    // Honor + pipelining: MessageSize 16 says the body is only 8 bytes, but 16 bytes are present — the
    // trailing 8 bytes (not a valid OPC UA header) must fall through to raw, and the whole thing must
    // round-trip byte-for-byte.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 50000, dstport: 4840}},
        {id: 'opcua', data: {messageType: 'MSG', chunk: 'F', messageSize: 16, body: '0102030405060708' + '0011223344556677'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'opcua', 'raw'])
    const opcua: any = Layer(decoded, 'opcua').data
    assert.strictEqual(opcua.messageSize, 16, 'honored MessageSize (not the 16-byte captured body length)')
    assert.strictEqual(opcua.body, '0102030405060708', 'body bounded to MessageSize (bytes [8..16))')
    assert.strictEqual(Layer(decoded, 'raw').data.data, '0011223344556677', 'trailing bytes → raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A TCP/4840 payload that is not OPC UA (an invalid message type) must fall through to raw, and a
// truncated OPC UA frame must decode without throwing.
test('OPC UA rejects a non-OPC-UA payload on port 4840 (falls through to raw); truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 50000, dstport: 4840}},
        {id: 'raw', data: {data: '585858461000000000000000'}} // "XXX" + "F" — invalid message type
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'opcua'), 'an invalid message type must not be claimed as OPC UA')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('opcua/hello').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 2))
})

// LE uint32 edge: a MessageSize with the high bit set (> 0x7FFFFFFF) must round-trip as an UNSIGNED value
// (the classic sign-extension trap — `(b0|b1<<8|b2<<16|b3<<24) >>> 0`), not a negative number.
test('OPC UA MessageSize high bit set round-trips as unsigned uint32', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 50000, dstport: 4840}},
        {id: 'opcua', data: {messageType: 'MSG', chunk: 'F', messageSize: 0x80000000, body: 'deadbeef'}}
    ])
    const hex: string = packet.toString('hex')
    const idx: number = hex.indexOf('4d534746')
    assert.strictEqual(hex.substr(idx + 8, 8), '00000080', 'MessageSize 0x80000000 is little-endian on the wire')
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const opcua: any = Layer(decoded, 'opcua').data
    assert.strictEqual(opcua.messageSize, 2147483648, 'high-bit MessageSize decodes as unsigned, not negative')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), hex, 'byte-perfect')
})
