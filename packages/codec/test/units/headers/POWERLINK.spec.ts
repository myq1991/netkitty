import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Ethernet POWERLINK (EtherType 0x88AB) SoA — Start of Asynchronous. 3-byte common header
// (MessageType 5 / Destination 255 / Source 240) + the SoA body, padded to the 60-byte minimum.
test('POWERLINK SoA: common header + payload + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('powerlink/soa').buffer)
    AssertLayers(decoded, ['eth', 'powerlink'])
    const epl: any = Layer(decoded, 'powerlink').data
    assert.strictEqual(epl.reserved, 0, 'reserved high bit clear')
    assert.strictEqual(epl.messageType, 5, 'SoA')
    assert.strictEqual(epl.destination, 255, 'broadcast destination node')
    assert.strictEqual(epl.source, 240, 'MN source node')
    // SoA body (offset 3 onward): NMTStatus 0x1d, flags, reserved, svid 1, target 1, EPLVersion 0x20, pad.
    assert.strictEqual(epl.payload, '1d0000010120' + '00'.repeat(37), 'body + Ethernet padding kept verbatim')
})

// PRes — Poll Response. MessageType 4 / Destination 240 / Source 1; the PRes body (flags, PDOVersion,
// Size 37, 37 PDO bytes) exactly fills the 60-byte frame (no Ethernet padding).
test('POWERLINK PRes: common header + PDO payload + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('powerlink/pres').buffer)
    AssertLayers(decoded, ['eth', 'powerlink'])
    const epl: any = Layer(decoded, 'powerlink').data
    assert.strictEqual(epl.messageType, 4, 'PRes')
    assert.strictEqual(epl.destination, 240, 'destination node')
    assert.strictEqual(epl.source, 1, 'controlled-node source')
    assert.strictEqual(
        epl.payload,
        '01002000002500112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233ff',
        'PRes flags/PDOVersion/Size + 37 PDO bytes kept verbatim'
    )
})

// Craft an EPL ASnd from scratch (MessageType 6) and require a byte-perfect encode → decode → re-encode.
// The payload is honored verbatim (the codec is a faithful executor — no length/padding is derived).
test('POWERLINK crafted ASnd: encode → decode → re-encode is byte-identical', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:11:1e:00:00:04', smac: '00:e0:4c:68:00:03', etherType: '88ab'}},
        // ASnd: MessageType 6, Destination 240, Source 240, ServiceID 1 (IdentResponse) + opaque body.
        {id: 'powerlink', data: {messageType: 6, destination: 240, source: 240, payload: '01aabbccddeeff'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'powerlink'])
    const epl: any = Layer(decoded, 'powerlink').data
    assert.strictEqual(epl.messageType, 6, 'ASnd')
    assert.strictEqual(epl.destination, 240)
    assert.strictEqual(epl.source, 240)
    assert.strictEqual(epl.payload, '01aabbccddeeff', 'payload honored verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// The Reserved high bit of the MessageType octet is kept verbatim (not forced to 0): a frame that sets
// it round-trips exactly, and the 7-bit message type is read independently of it.
test('POWERLINK preserves the Reserved high bit of the MessageType octet', async (): Promise<void> => {
    // MessageType octet 0x85 = reserved bit set (0x80) + message type 5 (SoA).
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:11:1e:00:00:03', smac: '00:e0:4c:68:00:01', etherType: '88ab'}},
        {id: 'powerlink', data: {reserved: 1, messageType: 5, destination: 255, source: 240, payload: '1d'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const epl: any = Layer(decoded, 'powerlink').data
    assert.strictEqual(epl.reserved, 1, 'reserved bit preserved')
    assert.strictEqual(epl.messageType, 5, 'message type read independently of the reserved bit')
    // byte 0 of the EPL header (frame offset 14) must be 0x85.
    assert.strictEqual(packet[14], 0x85, 'MessageType octet = reserved(0x80) | type 5')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a runt EPL frame (only the 3-byte common header, no body) must decode without throwing and
// still round-trip; and a frame truncated mid-common-header must survive decode.
test('POWERLINK truncation survives decode', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:11:1e:00:00:03', smac: '00:e0:4c:68:00:01', etherType: '88ab'}},
        {id: 'powerlink', data: {messageType: 5, destination: 255, source: 240}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const epl: any = Layer(decoded, 'powerlink').data
    assert.strictEqual(epl.payload, '', 'no body → empty payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')

    const full: Buffer = LoadPacket('powerlink/soa').buffer
    await AssertDecodeSurvives(full.subarray(0, 16))
})
