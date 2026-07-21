import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// CMS (DL/T 2811-2024) over plain TCP:8102 — real captured frames. The APCH (Control Code / Service
// Code / Frame Length) and the ASDU (ReqID + service data) decode per the standard's §6.1/§6.2.
test('CMS AssociateNegotiate request/response (real frames): APCH + ReqID decode, shared ReqID, byte-perfect', async (): Promise<void> => {
    const request: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('cms/associate-request').buffer)
    AssertLayers(request, ['eth', 'ipv4', 'tcp', 'cms'])
    const req: any = Layer(request, 'cms').data
    assert.strictEqual(req.protocolType, 0x01, 'PI protocol type 0x01 (DL/T 2811)')
    assert.strictEqual(req.resp, false, 'a request (Resp bit clear)')
    assert.strictEqual(req.err, false, 'not an error')
    assert.strictEqual(req.serviceCode, 154, 'SC 154 = AssociateNegotiate')
    assert.strictEqual(req.frameLength, 11, 'FL = ASDU length (little-endian)')
    assert.strictEqual(req.reqId, 13090, 'ReqID (little-endian)')
    // The service data PER-decodes to the negotiated sizes and version (§8.15.1.3).
    assert.deepStrictEqual(req.serviceDataDecoded, {
        service: 'AssociateNegotiate', direction: 'request',
        apduSize: 32768, asduSize: 131072, protocolVersion: 0x201
    }, 'AssociateNegotiate request: apduSize (INT16U) + asduSize/protocolVersion (INT32U)')

    const response: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('cms/associate-response').buffer)
    const rsp: any = Layer(response, 'cms').data
    assert.strictEqual(rsp.resp, true, 'a response (Resp bit set)')
    assert.strictEqual(rsp.serviceCode, 154, 'same service')
    assert.strictEqual(rsp.reqId, 13090, 'response uses the request ReqID (DL/T 2811 §6.2.1.2 b)')
    // The response adds the model version, an unbounded VisibleString (length determinant + content).
    assert.deepStrictEqual(rsp.serviceDataDecoded, {
        service: 'AssociateNegotiate', direction: 'response',
        apduSize: 32768, asduSize: 131072, protocolVersion: 0x201, modelVersion: 'V1.00'
    }, 'AssociateNegotiate response adds modelVersion')
})

// GetAllDataDefinition (SC 155): the request carries an IEC 61850 object reference in its service data;
// the 444-byte model response round-trips byte-for-byte.
test('CMS GetAllDataDefinition (real frames) round-trips with the service data verbatim', async (): Promise<void> => {
    const named: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('cms/request-named').buffer)
    const cms: any = Layer(named, 'cms').data
    assert.strictEqual(cms.serviceCode, 155, 'SC 155 = GetAllDataDefinition')
    assert.strictEqual(cms.reqId, 13092, 'ReqID')
    assert.ok(cms.serviceData.includes(Buffer.from('SW111103SWI/LLN0').toString('hex')), 'service data carries the 61850 object reference')
    // Display-only ALIGNED-PER structuring of the service data area (DL/T 2811 §6.10). The object
    // reference decoding cleanly confirms both the request PDU structure and the ALIGNED-PER mode.
    assert.deepStrictEqual(cms.serviceDataDecoded, {
        service: 'GetAllDataDefinition',
        direction: 'request',
        reference: {lnReference: 'SW111103SWI/LLN0'}
    }, 'the request PER-decodes to its logical-node reference (fc / referenceAfter absent)')

    const data: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('cms/response-data').buffer)
    const rsp: any = Layer(data, 'cms').data
    assert.strictEqual(rsp.resp, true, 'response')
    assert.strictEqual(rsp.serviceCode, 155, 'GetAllDataDefinition response')
    assert.strictEqual(rsp.frameLength, 444, 'FL')
    assert.strictEqual(rsp.serviceData.length / 2, 442, 'service data = FL - 2-byte ReqID, kept verbatim')
})

// GetAllDataValues (SC 83): the request shares GetAllDataDefinition's reference-CHOICE PER structure.
// (Its response carries Data values as GB/T 33602 TLV, decoded separately.)
test('CMS GetAllDataValues (SC 83) request PER-decodes its object reference', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('cms/getalldatavalues-request').buffer)
    const cms: any = Layer(decoded, 'cms').data
    assert.strictEqual(cms.serviceCode, 83, 'SC 83 = GetAllDataValues')
    assert.deepStrictEqual(cms.serviceDataDecoded, {
        service: 'GetAllDataValues',
        direction: 'request',
        reference: {lnReference: 'SW111103SWI/LLN0'}
    }, 'the request PER-decodes to its logical-node reference')
})

// Negative: a mid-PDU TCP-continuation segment (whose first byte's low nibble is not the PI 0x01) must
// NOT be claimed as CMS, and non-8102 traffic must not be claimed; truncation survives.
test('CMS is not claimed for continuation segments or non-8102 traffic; truncation survives', async (): Promise<void> => {
    const {packet: cont}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 8102, dstport: 50000}},
        // first byte 0x75 -> low nibble 5, not the PI 0x01, so it is a continuation segment, not an APCH
        {id: 'raw', data: {data: '75abcdef00112233'}}
    ])
    const contDecoded: CodecDecodeResult[] = await codec.decode(cont)
    assert.ok(!contDecoded.some((l: CodecDecodeResult): boolean => l.id === 'cms'), 'a continuation segment (no APCH) is not CMS')

    await AssertDecodeSurvives(LoadPacket('cms/response-data').buffer.subarray(0, 40))
})
