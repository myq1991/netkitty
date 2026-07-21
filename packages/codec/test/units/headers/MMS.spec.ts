import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

const ETH = {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}}
const IPV4 = {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}}

// The full IEC 61850 substation stack decodes end to end: TPKT / COTP / ISO-Session / MMS. The MMS layer
// folds the Presentation "fully-encoded-data" wrapper and exposes the presentation context + MMS PDU type.
test('MMS: the full TPKT/COTP/Session/MMS stack decodes and round-trips byte-perfect', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tpkt/cotp-dt').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tpkt', 'cotp', 'iso-session', 'mms'])
    const mms: any = Layer(decoded, 'mms').data
    assert.strictEqual(mms.presentationContext, 3, 'presentation-context-identifier (the MMS abstract syntax)')
    assert.strictEqual(mms.mmsPduType, 0x05, 'MMS PDU type 0x05 (NULL keep-alive)')
    assert.strictEqual(mms.message, '61093007020103a0020500', 'whole Presentation/MMS BER blob kept verbatim')
})

// A richer MMS PDU: a confirmed-request (BER tag 0xa0) wrapped in the Presentation fully-encoded-data.
// The parser reports the MMS PDU type and context, and the whole blob round-trips byte-for-byte.
test('MMS parses a confirmed-request PDU type and round-trips the BER blob verbatim', async (): Promise<void> => {
    // 61 (fully-encoded-data) -> 30 (PDV-list) -> 02 01 03 (context 3), a0 (data-values) -> a0 (confirmed-request) 02 01 02 (invokeID 2)
    const message: string = '610e300c020103a007a005020102'
    const {packet}: CodecEncodeResult = await codec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 50000, dstport: 102}},
        {id: 'tpkt', data: {version: 3, reserved: 0}},
        {id: 'cotp', data: {pduType: 0xf0, eot: true, tpduNr: 0}},
        {id: 'iso-session', data: {spdus: [{si: 1, li: 0, params: ''}, {si: 1, li: 0, params: ''}]}},
        {id: 'mms', data: {message: message}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tpkt', 'cotp', 'iso-session', 'mms'])
    const mms: any = Layer(decoded, 'mms').data
    assert.strictEqual(mms.presentationContext, 3, 'context 3')
    assert.strictEqual(mms.mmsPduType, 0xa0, 'MMS confirmed-request PDU (tag 0xa0)')
    assert.strictEqual(mms.message, message, 'BER blob verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Real ICCP/TASE.2 MMS PDUs reassembled from a TCP-segmented capture (mms.cap): the confirmed
// request/response service and invokeID are extracted from the BER blob for display, and the whole PDU
// round-trips byte-for-byte.
test('MMS extracts the confirmed service + invokeID from real Read and GetNameList PDUs', async (): Promise<void> => {
    // objectNames = the object/variable names referenced in the service body: domain-specific identifiers
    // (universal VisibleString) plus vmd-/aa-specific and domain-scope names (context-tagged printable
    // Identifiers). The Read request names all four of its variables; the GetNameList request names the
    // scope domain; the GetNameList response names the returned datasets. The Read response's value ("1.0")
    // is a context-tagged Data value (tag >= [3]), not a name, so it is correctly excluded.
    const cases: {name: string, pdu: number, invoke: number, service: string, names?: string[]}[] = [
        {name: 'mms/read-request', pdu: 0xa0, invoke: 4432, service: 'read', names: ['KIRKLAND', 'Bilateral_Table_ID', 'TASE2_Version', 'Supported_Features']},
        {name: 'mms/read-response', pdu: 0xa1, invoke: 4432, service: 'read'},
        {name: 'mms/getnamelist-request', pdu: 0xa0, invoke: 4433, service: 'getNameList', names: ['KIRKLAND']},
        {name: 'mms/getnamelist-response', pdu: 0xa1, invoke: 4433, service: 'getNameList', names: ['EMS_ANALOG_ICCP_IN', 'EMS_STATUS_ICCP_IN']}
    ]
    for (const c of cases) {
        const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket(c.name).buffer)
        AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tpkt', 'cotp', 'iso-session', 'mms'])
        const mms: any = Layer(decoded, 'mms').data
        assert.strictEqual(mms.mmsPduType, c.pdu, `${c.name}: MMS PDU type`)
        assert.strictEqual(mms.mmsInvokeID, c.invoke, `${c.name}: invokeID`)
        assert.strictEqual(mms.mmsService, c.service, `${c.name}: confirmed service`)
        assert.deepStrictEqual(mms.mmsObjectNames, c.names, `${c.name}: object names`)
    }
})

// A confirmed-error PDU (0xa2) starts with the invokeID but its second element is modifierPosition/
// serviceError, NOT a ConfirmedService CHOICE — so the invokeID is extracted but the service stays blank
// (rather than mislabeling the serviceError's tag as a service).
test('MMS confirmed-error: invokeID is extracted but no service is inferred', async (): Promise<void> => {
    // 61 -> 30 -> 020103(ctx 3) -> a0(pdv) -> a2(confirmed-error){ 020102(invokeID 2), a0028000(serviceError) }
    const message: string = '6110300e020103a009a207020102a0028000'
    const {packet}: CodecEncodeResult = await codec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 50000, dstport: 102}},
        {id: 'tpkt', data: {version: 3, reserved: 0}},
        {id: 'cotp', data: {pduType: 0xf0, eot: true, tpduNr: 0}},
        {id: 'iso-session', data: {spdus: [{si: 1, li: 0, params: ''}, {si: 1, li: 0, params: ''}]}},
        {id: 'mms', data: {message: message}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const mms: any = Layer(decoded, 'mms').data
    assert.strictEqual(mms.mmsPduType, 0xa2, 'confirmed-error PDU')
    assert.strictEqual(mms.mmsInvokeID, 2, 'invokeID extracted')
    assert.strictEqual(mms.mmsService, undefined, 'no service inferred for an error PDU')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Off-parent guard: a 0x61 BER blob directly on TCP (no ISO-Session parent) must NOT be claimed as MMS;
// truncation survives.
test('MMS is only claimed above ISO Session; truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        ETH, IPV4,
        {id: 'tcp', data: {srcport: 40000, dstport: 40001}},
        {id: 'raw', data: {data: '61093007020103a0020500'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'mms'), 'no ISO-Session parent -> not mms')

    await AssertDecodeSurvives(LoadPacket('tpkt/cotp-dt').buffer.subarray(0, 62))
})
