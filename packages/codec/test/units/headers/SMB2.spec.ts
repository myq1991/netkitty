import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// The full NEGOTIATE Request body (StructureSize 36, DialectCount 2, SecurityMode signing-enabled,
// ClientGuid, dialects 0x0202 SMB 2.0.2 + 0x0210 SMB 2.1).
const NEGOTIATE_BODY: string = '240002000100000000000000112233445566778899aabbccddeeff00000000000000000002021002'

// SMB2 (tcp:445) NEGOTIATE Request over Direct TCP — 4-byte transport prefix + 64-byte SMB2 header + body.
test('SMB2 NEGOTIATE: transport prefix + LE header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('smb2/negotiate').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'smb2'])
    const smb2: any = Layer(decoded, 'smb2').data
    assert.strictEqual(smb2.transportType, 0, 'Direct TCP session-message type')
    assert.strictEqual(smb2.streamProtocolLength, 104, '24-bit stream length = 64-byte header + 40-byte body')
    assert.strictEqual(smb2.protocolId, 'fe534d42', "0xFE 'S' 'M' 'B' magic")
    assert.strictEqual(smb2.structureSize, 64, 'SMB2 header StructureSize is always 64 (little-endian)')
    assert.strictEqual(smb2.command, 0, 'NEGOTIATE')
    assert.strictEqual(smb2.creditReqResp, 1, 'CreditRequest 1 (little-endian)')
    assert.strictEqual(smb2.messageId, '0000000000000000', 'MessageId 0')
    assert.strictEqual(smb2.sessionId, '0000000000000000', 'SessionId 0')
    assert.strictEqual(smb2.body, NEGOTIATE_BODY, 'NEGOTIATE Request body kept verbatim')
})

// Crafting: a TREE_CONNECT (command 3) with the StreamProtocolLength auto-computed from the header + body.
test('SMB2 faithfully encodes a crafted TREE_CONNECT and auto-computes the StreamProtocolLength', async (): Promise<void> => {
    const treeBody: string = '090000004800120005005c005c003100320037002e0030002e0030002e0031005c0049005000430024'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 52001, dstport: 445}},
        {id: 'smb2', data: {protocolId: 'fe534d42', structureSize: 64, command: 3, creditReqResp: 1, messageId: '0300000000000000', body: treeBody}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'smb2'])
    const smb2: any = Layer(decoded, 'smb2').data
    assert.strictEqual(smb2.command, 3, 'TREE_CONNECT')
    assert.strictEqual(smb2.streamProtocolLength, 64 + treeBody.length / 2, 'auto-computed = 64-byte header + body bytes')
    assert.strictEqual(smb2.body, treeBody, 'TREE_CONNECT body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted message supplies an explicit StreamProtocolLength — it must be honored
// verbatim (not overwritten by the derived value), so a message carrying any length round-trips.
test('SMB2 honors an explicitly supplied StreamProtocolLength (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 445, dstport: 52001}},
        // READ response (command 8) with an explicit, larger-than-derived StreamProtocolLength.
        {id: 'smb2', data: {protocolId: 'fe534d42', structureSize: 64, command: 8, streamProtocolLength: 70, messageId: '0800000000000000', body: '110001000000000000000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const smb2: any = Layer(decoded, 'smb2').data
    assert.strictEqual(smb2.command, 8, 'READ')
    assert.strictEqual(smb2.streamProtocolLength, 70, 'supplied StreamProtocolLength honored')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/445 payload whose 4-byte ProtocolId is not the 0xFE 'S' 'M' 'B' magic must NOT be
// claimed as SMB2 (falls through to raw); and a truncated SMB2 message must survive decode without throwing.
test('SMB2 rejects a non-magic payload on port 445, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 445}},
        // transport prefix then a bogus ProtocolId (not fe534d42, not SMB1's ff534d42) — no signature.
        {id: 'raw', data: {data: '0000000cdeadbeefcafebabe0badf00d'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'smb2'), 'non-magic payload must not be claimed as SMB2')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('smb2/negotiate').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})

// Protocol-specific edge: two SMB2 messages pipelined in one TCP segment. The first is bounded by its
// StreamProtocolLength, so its body does NOT swallow the trailing message; the trailing bytes fall
// through to raw (a leaf header advances only over its own message and does not re-match itself, matching
// the length-bounded-TCP-payload precedent). Both directions round-trip byte-for-byte.
test('SMB2 pipelining: the first message is bounded by its StreamProtocolLength; the trailing message falls through to raw', async (): Promise<void> => {
    // First: a minimal NEGOTIATE (empty body) => stream length 64. Second: another minimal message.
    const emptyHeader: string = 'fe534d42' + '4000' + '0000' + '00000000' + '0000' + '0100' + '00000000' + '00000000'
        + '0000000000000000' + '00000000' + '00000000' + '0000000000000000' + '00000000000000000000000000000000'
    const first: string = '00000040' + emptyHeader                    // prefix len 64 + 64-byte header
    const second: string = '00000040' + emptyHeader                   // a second, identical message
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 445, dstport: 52001}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'smb2', 'raw'])
    const smb2: any = Layer(decoded, 'smb2').data
    assert.strictEqual(smb2.command, 0, 'first is NEGOTIATE')
    assert.strictEqual(smb2.streamProtocolLength, 64, 'first message bounded by its StreamProtocolLength')
    assert.strictEqual(smb2.body, '', 'empty body — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing message left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
