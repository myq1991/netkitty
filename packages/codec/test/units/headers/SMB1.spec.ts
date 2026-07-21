import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertLayers, Layer} from '../../lib/RoundTrip'
import {Codec} from '../../../src/lib/codec/Codec'
import {SMB1} from '../../../src/lib/codec/headers/SMB1'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

//SMB1 is not (yet) in the built-in registry, so this spec drives a codec that layers SMB1 on top of the
//built-ins. The Layer/AssertLayers helpers are codec-agnostic (they inspect decode results only).
const smb1Codec: Codec = new Codec([SMB1])

async function AssertRoundTrip(buffer: Buffer): Promise<CodecDecodeResult[]> {
    const decoded: CodecDecodeResult[] = await smb1Codec.decode(buffer)
    const encoded: CodecEncodeResult = await smb1Codec.encode(decoded)
    assert.strictEqual(encoded.packet.toString('hex'), buffer.toString('hex'), 'decode→encode round-trip must reproduce the original bytes')
    return decoded
}

async function AssertDecodeSurvives(buffer: Buffer): Promise<CodecDecodeResult[]> {
    const decoded: CodecDecodeResult[] = await smb1Codec.decode(buffer)
    assert.ok(decoded.length > 0, 'decoder must always produce at least one layer')
    return decoded
}

// The full NEGOTIATE Protocol Request parameter/data block (WordCount 0, ByteCount 12, dialect string
// 0x02 "NT LM 0.12" NUL-terminated).
const NEGOTIATE_BODY: string = '000c00024e54204c4d20302e313200'

// SMB1 (tcp:445) NEGOTIATE Protocol Request over Direct TCP — 4-byte transport prefix + 32-byte SMB1
// header + parameter/data block.
test('SMB1 NEGOTIATE: transport prefix + LE header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('smb1/negotiate').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'smb1'])
    const smb1: any = Layer(decoded, 'smb1').data
    assert.strictEqual(smb1.transportType, 0, 'Direct TCP session-message type')
    assert.strictEqual(smb1.streamProtocolLength, 47, '24-bit stream length = 32-byte header + 15-byte body')
    assert.strictEqual(smb1.protocolId, 'ff534d42', "0xFF 'S' 'M' 'B' magic")
    assert.strictEqual(smb1.command, 0x72, 'NEGOTIATE')
    assert.strictEqual(smb1.status, 0, 'STATUS_SUCCESS (little-endian)')
    assert.strictEqual(smb1.flags, 0x18, 'Flags 0x18')
    assert.strictEqual(smb1.flags2, 0xc853, 'Flags2 0xc853 (little-endian)')
    assert.strictEqual(smb1.tid, 0xffff, 'Tree Id 0xffff (little-endian)')
    assert.strictEqual(smb1.pidLow, 0xfeff, 'PID Low 0xfeff (little-endian)')
    assert.strictEqual(smb1.uid, 0, 'User Id 0')
    assert.strictEqual(smb1.mid, 0, 'Multiplex Id 0')
    assert.strictEqual(smb1.body, NEGOTIATE_BODY, 'parameter/data block kept verbatim')
})

// Crafting: a TREE_CONNECT_ANDX (command 0x75) with the StreamProtocolLength auto-computed from the header
// + body.
test('SMB1 faithfully encodes a crafted TREE_CONNECT_ANDX and auto-computes the StreamProtocolLength', async (): Promise<void> => {
    const treeBody: string = '04ff000000000100010000005c005c003100320037002e0030002e0030002e0031005c0049005000430024000000'
    const {packet}: CodecEncodeResult = await smb1Codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 52001, dstport: 445}},
        {id: 'smb1', data: {protocolId: 'ff534d42', command: 0x75, flags: 0x18, flags2: 0xc853, tid: 0x0800, uid: 0x0800, mid: 1, body: treeBody}}
    ])
    const decoded: CodecDecodeResult[] = await smb1Codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'smb1'])
    const smb1: any = Layer(decoded, 'smb1').data
    assert.strictEqual(smb1.command, 0x75, 'TREE_CONNECT_ANDX')
    assert.strictEqual(smb1.streamProtocolLength, 32 + treeBody.length / 2, 'auto-computed = 32-byte header + body bytes')
    assert.strictEqual(smb1.body, treeBody, 'TREE_CONNECT_ANDX body')
    assert.strictEqual((await smb1Codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted message supplies an explicit StreamProtocolLength — it must be honored
// verbatim (not overwritten by the derived value), so a message carrying any length round-trips.
test('SMB1 honors an explicitly supplied StreamProtocolLength (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await smb1Codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 445, dstport: 52001}},
        // SESSION_SETUP_ANDX response (command 0x73) with an explicit, larger-than-derived length.
        {id: 'smb1', data: {protocolId: 'ff534d42', command: 0x73, streamProtocolLength: 50, flags: 0x98, flags2: 0xc853, uid: 0x0800, mid: 1, body: '04ff00000000000000000000'}}
    ])
    const decoded: CodecDecodeResult[] = await smb1Codec.decode(packet)
    const smb1: any = Layer(decoded, 'smb1').data
    assert.strictEqual(smb1.command, 0x73, 'SESSION_SETUP_ANDX')
    assert.strictEqual(smb1.streamProtocolLength, 50, 'supplied StreamProtocolLength honored')
    assert.strictEqual((await smb1Codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/445 payload whose 4-byte Protocol id is not the 0xFF 'S' 'M' 'B' magic must NOT be
// claimed as SMB1 (falls through to raw); and a truncated SMB1 message must survive decode without throwing.
test('SMB1 rejects a non-magic payload on port 445, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await smb1Codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 445}},
        // transport prefix then a bogus Protocol id (not ff534d42, not SMB2's fe534d42) — no signature.
        {id: 'raw', data: {data: '0000000c1234abcddeadbeef0badf00d'}}
    ])
    const decoded: CodecDecodeResult[] = await smb1Codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'smb1'), 'non-magic payload must not be claimed as SMB1')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('smb1/negotiate').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})

// Protocol-specific edge: two SMB1 messages pipelined in one TCP segment. The first is bounded by its
// StreamProtocolLength, so its body does NOT swallow the trailing message; the trailing bytes fall through
// to raw (a leaf header advances only over its own message and does not re-match itself, matching the
// length-bounded-TCP-payload precedent). Both directions round-trip byte-for-byte.
test('SMB1 pipelining: the first message is bounded by its StreamProtocolLength; the trailing message falls through to raw', async (): Promise<void> => {
    // A minimal SMB1 header (32 bytes) with an empty parameter/data block => stream length 32.
    const emptyHeader: string = 'ff534d42' + '72' + '00000000' + '18' + '53c8' + '0000'
        + '0000000000000000' + '0000' + 'ffff' + 'fffe' + '0000' + '0000'
    const first: string = '00000020' + emptyHeader                    // prefix len 32 + 32-byte header
    const second: string = '00000020' + emptyHeader                   // a second, identical message
    const {packet}: CodecEncodeResult = await smb1Codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 445, dstport: 52001}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await smb1Codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'smb1', 'raw'])
    const smb1: any = Layer(decoded, 'smb1').data
    assert.strictEqual(smb1.command, 0x72, 'first is NEGOTIATE')
    assert.strictEqual(smb1.streamProtocolLength, 32, 'first message bounded by its StreamProtocolLength')
    assert.strictEqual(smb1.body, '', 'empty body — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing message left as raw')
    assert.strictEqual((await smb1Codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
