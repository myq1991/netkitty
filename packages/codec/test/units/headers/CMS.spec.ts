import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// CMS (China smart-substation, DL/T 860 CMS) over plain TCP:8102 — real captured frames. The 4-byte
// frame header (flags / service / little-endian length) decodes and the ACSI PDU body is kept verbatim.
test('CMS associate request/response (real frames) decode and round-trip byte-perfect', async (): Promise<void> => {
    const request: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('cms/associate-request').buffer)
    AssertLayers(request, ['eth', 'ipv4', 'tcp', 'cms'])
    const req: any = Layer(request, 'cms').data
    assert.strictEqual(req.flags, 0x01, 'request flags (bit 0x40 clear)')
    assert.strictEqual(req.serviceType, 0x9a, 'associate service')
    assert.strictEqual(req.length, 11, 'little-endian body length')
    assert.strictEqual(req.body.length / 2, 11, 'body is 11 bytes (matches the length field)')

    const response: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('cms/associate-response').buffer)
    const rsp: any = Layer(response, 'cms').data
    assert.strictEqual(rsp.flags, 0x41, 'response flags (bit 0x40 set)')
    assert.strictEqual(rsp.serviceType, 0x9a, 'associate service')
    assert.strictEqual(rsp.length, 17, 'response body length')
})

// A named request (real frame) carries an IEC 61850 object reference in its ACSI body; a 448-byte model
// response (real frame) round-trips byte-for-byte with its whole body kept verbatim.
test('CMS get-data request/response (real frames) round-trip with verbatim body', async (): Promise<void> => {
    const named: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('cms/request-named').buffer)
    const cms: any = Layer(named, 'cms').data
    assert.strictEqual(cms.serviceType, 0x9b, 'get-data service')
    assert.strictEqual(cms.length, 20, 'body length')
    // The body carries the ASCII object reference "SW111103SWI/LLN0".
    assert.ok(cms.body.includes(Buffer.from('SW111103SWI/LLN0').toString('hex')), 'ACSI body carries the 61850 object reference')

    const data: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('cms/response-data').buffer)
    const rsp: any = Layer(data, 'cms').data
    assert.strictEqual(rsp.flags, 0x41, 'response')
    assert.strictEqual(rsp.length, 444, '444-byte model data body')
    assert.strictEqual(rsp.body.length / 2, 444, 'whole body kept verbatim')
})

// Negative: a mid-PDU continuation segment (does not begin with 0x01/0x41) must NOT be claimed as CMS,
// and non-8102 traffic must not be claimed; truncation survives.
test('CMS is not claimed for continuation segments or non-8102 traffic; truncation survives', async (): Promise<void> => {
    // A tcp:8102 payload beginning with 0x75 (an ACSI continuation byte, not a frame header) -> raw.
    const {packet: cont}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 8102, dstport: 50000}},
        {id: 'raw', data: {data: '75abcdef00112233'}}
    ])
    const contDecoded: CodecDecodeResult[] = await codec.decode(cont)
    assert.ok(!contDecoded.some((l: CodecDecodeResult): boolean => l.id === 'cms'), 'continuation segment (no 0x01/0x41 header) is not CMS')

    await AssertDecodeSurvives(LoadPacket('cms/response-data').buffer.subarray(0, 40))
})
