import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {Codec} from '../../../src/Codec'
import {S7comm} from '../../../src/headers/S7comm'
import {FlexibleObject} from '../../../src/lib/FlexibleObject'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// ⚠️ Integration note: S7comm rides ON TOP of a COTP DT TPDU (prev.id === 'cotp' + 0x32 signature). The
// built-in COTP header currently CONSUMES its whole ISO/MMS user data into `cotp.data` (its headerLength
// spans the payload), so with the default codec the S7 PDU is kept verbatim as cotp.data and S7comm is
// never routed. Wiring S7comm as a real child requires COTP to hand off its payload instead of swallowing
// it — a change to the shared COTP header, deferred to the serial integration pass. Until then these tests
// exercise S7comm directly, constructing it under a synthesized COTP/TPKT parent context (the
// "直接构造带 prev 的场景" path), plus the full-frame COTP round-trip that proves the fixture bytes.

// Build the {tpkt, cotp} previous-module context S7comm reads: its #payloadEnd() double-cap scans
// prevCodecModules for the enclosing TPKT length; match()/decode read prev.id === 'cotp'.
function prevModules(tpktStart: number, tpktLength: number): any[] {
    const tpkt: any = {id: 'tpkt', startPos: tpktStart, instance: {length: {getValue: (): number => tpktLength}}}
    const cotp: any = {id: 'cotp', startPos: tpktStart + 4, instance: {}}
    return [tpkt, cotp]
}

// Decode an S7comm PDU sitting at `startPos` in `packet`, under a synthesized TPKT/COTP parent.
async function decodeS7(packet: Buffer, startPos: number, tpktStart: number, tpktLength: number): Promise<S7comm> {
    const module: S7comm = S7comm.CREATE_INSTANCE({packet: packet, startPos: startPos, postHandlers: []}, prevModules(tpktStart, tpktLength)) as S7comm
    await module.decode()
    return module
}

// Encode a decoded S7comm data tree back into a fresh buffer (offset 0) and return the bytes.
async function encodeS7(data: any): Promise<Buffer> {
    const codecData: any = {packet: Buffer.alloc(0), startPos: 0, postHandlers: []}
    const module: S7comm = S7comm.CREATE_INSTANCE(codecData, prevModules(0, 65535)) as S7comm
    module.instance = new FlexibleObject(module.validate(data))
    await module.encode()
    return codecData.packet
}

// The S7comm PDU begins at offset 61 in the fixture frame (14 eth + 20 ipv4 + 20 tcp + 4 tpkt + 3 cotp).
const S7_OFFSET: number = 61
const TPKT_OFFSET: number = 54
const TPKT_LENGTH: number = 25

// The fixture frame's whole eth/ipv4/tcp/tpkt/cotp/s7comm stack round-trips byte-for-byte through the
// default codec: COTP now exposes its DT+EOT payload as a child, and S7comm claims it by the 0x32
// signature — so cotp.data is empty and the S7 PDU lives in its own s7comm layer.
test('S7comm fixture: full COTP-carried frame round-trips and S7comm decodes above COTP', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('s7comm/setup-communication').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tpkt', 'cotp', 's7comm'])
    const cotp: any = Layer(decoded, 'cotp').data
    assert.strictEqual(cotp.data, '', 'COTP no longer consumes the payload — it is exposed as the s7comm child')
    const s7: any = Layer(decoded, 's7comm').data
    assert.strictEqual(s7.protocolId, 0x32, 'the S7 PDU (Protocol Id 0x32) decodes as the s7comm layer')
    assert.strictEqual(s7.rosctr, 1, 'ROSCTR = Job (Setup Communication)')
})

// S7comm decode of the fixture's Setup Communication Job PDU: fixed 10-byte header fields, then the
// 8-byte Parameter section, no Data — and re-encoding the decoded tree reproduces the PDU byte-for-byte.
test('S7comm Setup Communication (Job): header + parameter decode + byte-perfect round-trip', async (): Promise<void> => {
    const full: Buffer = LoadPacket('s7comm/setup-communication').buffer
    const s7: S7comm = await decodeS7(full, S7_OFFSET, TPKT_OFFSET, TPKT_LENGTH)
    const data: any = s7.instance.getValue()
    assert.strictEqual(data.protocolId, 0x32, 'Protocol Id 0x32')
    assert.strictEqual(data.rosctr, 1, 'ROSCTR = Job')
    assert.strictEqual(data.redundancyId, '0000', 'Redundancy Id reserved 0')
    assert.strictEqual(data.pduReference, 1024, 'PDU Reference 0x0400')
    assert.strictEqual(data.parameterLength, 8, 'Parameter Length 8')
    assert.strictEqual(data.dataLength, 0, 'Data Length 0')
    assert.strictEqual(data.parameter, 'f0000001000103c0', 'Setup Communication parameter kept verbatim')
    assert.strictEqual(data.data, '', 'no Data section')
    assert.strictEqual(s7.length, 18, 'S7 header (10) + parameter (8) + data (0)')
    const reencoded: Buffer = await encodeS7(data)
    assert.strictEqual(reencoded.toString('hex'), full.subarray(S7_OFFSET).toString('hex'), 'S7 PDU round-trips byte-for-byte')
})

// Ack_Data (ROSCTR 3) carries the 2-byte Error Class + Error Code that Job/Userdata PDUs do not; the two
// length fields are honor-else-derive (omitted here → derived from the section hex). A Read Var response.
test('S7comm Ack_Data: the ROSCTR-conditional error field decodes and lengths derive; round-trips', async (): Promise<void> => {
    //   32 03 | 0000 | 0400 | paramLen 0002 | dataLen 0005 | err 0000 | param f005 | data ff04002001
    const pdu: string = '3203000004000002000500' + '00' + 'f005' + 'ff04002001'
    const packet: Buffer = Buffer.from(pdu, 'hex')
    const s7: S7comm = await decodeS7(packet, 0, 0, 4 + packet.length)
    const data: any = s7.instance.getValue()
    assert.strictEqual(data.rosctr, 3, 'ROSCTR = Ack_Data')
    assert.strictEqual(data.errorClass, 0, 'Error Class decoded (present only on Ack/Ack_Data)')
    assert.strictEqual(data.errorCode, 0, 'Error Code decoded')
    assert.strictEqual(data.parameterLength, 2, 'Parameter Length')
    assert.strictEqual(data.dataLength, 5, 'Data Length')
    assert.strictEqual(data.parameter, 'f005', 'parameter after the 12-byte header (error field included)')
    assert.strictEqual(data.data, 'ff04002001', 'data section')
    // Re-derive lengths from the sections (omit them) — must reproduce the same wire bytes.
    const derived: Buffer = await encodeS7({protocolId: 0x32, rosctr: 3, redundancyId: '0000', pduReference: 1024, errorClass: 0, errorCode: 0, parameter: 'f005', data: 'ff04002001'})
    assert.strictEqual(derived.toString('hex'), pdu, 'omitted lengths derived from the section byte lengths')
    // Full decode→encode identity.
    assert.strictEqual((await encodeS7(data)).toString('hex'), pdu, 'Ack_Data PDU round-trips byte-for-byte')
})

// honor-else-derive: an explicitly supplied (deliberately wrong) Parameter Length is written verbatim,
// never recomputed — a crafted PDU may carry any length and must reproduce it.
test('S7comm honors an explicitly supplied Parameter Length (does not derive over it)', async (): Promise<void> => {
    const bytes: Buffer = await encodeS7({rosctr: 1, pduReference: 0, parameterLength: 99, parameter: 'f0000001000103c0'})
    // Parameter Length field is the 2 bytes at offset 6 → 0x0063 = 99, not the derived 8.
    assert.strictEqual(bytes.subarray(6, 8).toString('hex'), '0063', 'supplied Parameter Length honored verbatim')
})

// Negative / robustness: a PDU truncated inside the Parameter section must decode best-effort (never
// throw) and re-encode to exactly the surviving bytes.
test('S7comm truncation survives and round-trips the surviving bytes', async (): Promise<void> => {
    const full: Buffer = LoadPacket('s7comm/setup-communication').buffer
    const truncated: Buffer = full.subarray(0, full.length - 4) // cut into the parameter section
    const s7: S7comm = await decodeS7(truncated, S7_OFFSET, TPKT_OFFSET, TPKT_LENGTH)
    const data: any = s7.instance.getValue()
    assert.strictEqual(data.protocolId, 0x32, 'header still decodes under truncation')
    assert.strictEqual(data.parameter, 'f0000001', 'parameter clamped to the surviving bytes')
    assert.strictEqual((await encodeS7(data)).toString('hex'), truncated.subarray(S7_OFFSET).toString('hex'), 'surviving bytes round-trip')
})

// Negative: S7comm requires a COTP parent. A TCP payload that starts with 0x32 but has NO COTP parent
// (here a bare raw TCP payload) must NOT be claimed as s7comm — it falls through to raw.
test('S7comm is not claimed without a COTP parent', async (): Promise<void> => {
    const localCodec: Codec = new Codec([S7comm])
    const {packet}: CodecEncodeResult = await localCodec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 102}},
        {id: 'raw', data: {data: '32010000040000080000f0000001000103c0'}} // looks like S7comm, but no COTP parent
    ])
    const decoded: CodecDecodeResult[] = await localCodec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 's7comm'), 'S7comm must require a COTP parent')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
})

// Negative: under a COTP parent but WITHOUT the 0x32 Protocol Id signature, match() must reject.
test('S7comm match() requires the 0x32 Protocol Id under COTP', async (): Promise<void> => {
    const packet: Buffer = Buffer.from('33010000040000080000', 'hex') // first byte 0x33, not 0x32
    const probe: S7comm = S7comm.CREATE_INSTANCE({packet: packet, startPos: 0, postHandlers: []}, prevModules(0, 14)) as S7comm
    assert.strictEqual(probe.match(), false, 'a non-0x32 leading byte under COTP is not S7comm')
    const ok: S7comm = S7comm.CREATE_INSTANCE({packet: Buffer.from('32010000040000080000', 'hex'), startPos: 0, postHandlers: []}, prevModules(0, 14)) as S7comm
    assert.strictEqual(ok.match(), true, '0x32 under a COTP parent matches')
})
