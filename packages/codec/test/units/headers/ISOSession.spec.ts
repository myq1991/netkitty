import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

const ETH = {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}}
const IPV4 = {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}}

// The MMS data phase: an ISO-Session GIVE-TOKENS + DATA-TRANSFER pair (01 00 01 00) decodes as an
// iso-session layer above COTP, and the Presentation/MMS PDU that follows is handed off as a child.
test('ISO Session: MMS data-phase SPDUs decode above COTP and round-trip byte-perfect', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tpkt/cotp-dt').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tpkt', 'cotp', 'iso-session', 'mms'])
    const session: any = Layer(decoded, 'iso-session').data
    assert.strictEqual(session.spdus.length, 2, 'GIVE-TOKENS + DATA-TRANSFER')
    assert.deepStrictEqual(session.spdus[0], {si: 1, li: 0, params: ''}, 'GIVE-TOKENS SPDU (SI 1, no params)')
    assert.deepStrictEqual(session.spdus[1], {si: 1, li: 0, params: ''}, 'DATA-TRANSFER SPDU (SI 1, no params)')
    assert.strictEqual((Layer(decoded, 'mms').data as any).message, '61093007020103a0020500', 'Presentation/MMS PDU is the mms child')
})

// A connection-phase CONNECT SPDU (SI 13) with variable parameters is kept verbatim, and the presentation
// that follows falls to raw — round-tripping byte-for-byte.
test('ISO Session: a CONNECT SPDU with parameters round-trips and hands off its payload', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 50000, dstport: 102}},
        {id: 'tpkt', data: {version: 3, reserved: 0}},
        {id: 'cotp', data: {pduType: 0xf0, eot: true, tpduNr: 0}}, // DT + EOT so COTP exposes the child
        {id: 'iso-session', data: {spdus: [{si: 13, params: '05061301000116'}]}}, // CONNECT SPDU, LI derived
        {id: 'raw', data: {data: '31820100'}} // a presentation-looking remainder
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tpkt', 'cotp', 'iso-session', 'raw'])
    const session: any = Layer(decoded, 'iso-session').data
    assert.strictEqual(session.spdus[0].si, 13, 'CONNECT SPDU')
    assert.strictEqual(session.spdus[0].li, 7, 'LI derived from the 7-byte parameter block')
    assert.strictEqual(session.spdus[0].params, '05061301000116', 'CONNECT parameters kept verbatim')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, '31820100', 'presentation remainder is the child')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// The MMS connection phase: real ICCP/TASE.2 Associate PDUs whose ISO 8327 CONNECT (SI 13) / ACCEPT
// (SI 14) SPDU embeds the ACSE APDU in its user data. The session bytes round-trip verbatim and the ACSE
// APDU type (AARQ / AARE) is surfaced for display.
test('ISO Session: a CONNECT SPDU exposes the embedded ACSE AARQ; ACCEPT exposes AARE', async (): Promise<void> => {
    const request: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('mms/associate-request').buffer)
    AssertLayers(request, ['eth', 'ipv4', 'tcp', 'tpkt', 'cotp', 'iso-session'])
    const reqSession: any = Layer(request, 'iso-session').data
    assert.strictEqual(reqSession.spdus[0].si, 13, 'CONNECT SPDU')
    assert.strictEqual(reqSession.acseType, 'AARQ', 'ACSE Associate Request embedded in the CONNECT user data')
    assert.strictEqual(reqSession.acseAppContext, '1.0.9506.1.1', 'ACSE application-context-name OID (ISO 9506 MMS)')
    assert.strictEqual(reqSession.acseCalledApTitle, '1.1.2', 'called-AP-title [2] OID')
    assert.strictEqual(reqSession.acseCallingApTitle, '1.1.1', 'calling-AP-title [6] OID')
    assert.strictEqual(reqSession.mmsInitMaxServOutstandingCalling, 20, 'MMS initiate proposedMaxServOutstandingCalling')
    assert.strictEqual(reqSession.mmsInitNestingLevel, 4, 'MMS initiate data-structure nesting level')
    assert.strictEqual(reqSession.mmsInitVersion, 1, 'MMS initiate version')

    const response: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('mms/associate-response').buffer)
    const rspSession: any = Layer(response, 'iso-session').data
    assert.strictEqual(rspSession.spdus[0].si, 14, 'ACCEPT SPDU')
    assert.strictEqual(rspSession.acseType, 'AARE', 'ACSE Associate Response embedded in the ACCEPT user data')
    assert.strictEqual(rspSession.acseAppContext, '1.0.9506.1.1', 'ACSE application-context-name OID (ISO 9506 MMS)')
    assert.strictEqual(rspSession.acseRespondingApTitle, '1.1.2', 'responding-AP-title [4] OID')
})

// Off-parent guard: a TCP payload that happens to start with a session SI byte must NOT be claimed as
// iso-session (it only rides above COTP); and a COTP DT that is NOT end-of-TSDU (EOT=0, i.e. fragmented)
// keeps its user data in cotp.data and never exposes a session child.
test('ISO Session is only claimed above COTP; a fragmented (EOT=0) DT does not expose it', async (): Promise<void> => {
    // Directly on TCP (no COTP parent): must not be iso-session.
    const {packet: onTcp}: CodecEncodeResult = await codec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 40000, dstport: 40001}},
        {id: 'raw', data: {data: '01000100'}}
    ])
    const tcpDecoded: CodecDecodeResult[] = await codec.decode(onTcp)
    assert.ok(!tcpDecoded.some((l: CodecDecodeResult): boolean => l.id === 'iso-session'), 'no COTP parent -> not iso-session')

    // A fragmented DT (EOT=0): COTP keeps the payload verbatim in cotp.data, so no session child appears.
    const {packet: frag}: CodecEncodeResult = await codec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 50000, dstport: 102}},
        {id: 'tpkt', data: {version: 3, reserved: 0}},
        {id: 'cotp', data: {pduType: 0xf0, eot: false, tpduNr: 0, data: '01000100610905'}}
    ])
    const fragDecoded: CodecDecodeResult[] = await codec.decode(frag)
    assert.ok(!fragDecoded.some((l: CodecDecodeResult): boolean => l.id === 'iso-session'), 'a fragmented (EOT=0) DT does not expose a session child')
    assert.strictEqual((Layer(fragDecoded, 'cotp').data as any).data, '01000100610905', 'COTP keeps the fragment verbatim')

    await AssertDecodeSurvives(LoadPacket('tpkt/cotp-dt').buffer.subarray(0, 60))
})
