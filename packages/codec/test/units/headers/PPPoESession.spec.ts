import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// PPPoE Session Stage (ethertype 0x8864) carrying an LCP Configure-Request — 6-byte PPPoE header +
// 2-byte PPP protocol + LCP payload, byte-perfect round-trip.
test('PPPoE Session: header + PPP protocol + payload + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('pppoe/session-lcp').buffer)
    AssertLayers(decoded, ['eth', 'pppoe-sess'])
    const pppoe: any = Layer(decoded, 'pppoe-sess').data
    assert.strictEqual(pppoe.version, 1, 'version 1')
    assert.strictEqual(pppoe.type, 1, 'type 1')
    assert.strictEqual(pppoe.code, 0, 'Session Stage code 0x00')
    assert.strictEqual(pppoe.sessionId, 1, 'session id 0x0001')
    assert.strictEqual(pppoe.length, 10, 'payload length = 2-byte protocol + 8-byte LCP')
    assert.strictEqual(pppoe.pppProtocol, 'c021', 'PPP protocol LCP')
    assert.strictEqual(pppoe.payload, '01010008010405dc', 'LCP Configure-Request with MRU option')
})

// honor-else-derive Length: encode with no Length supplied — it must be derived as 2 + payload bytes.
test('PPPoE derives the Length from the payload when not supplied', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '00:aa:bb:cc:dd:ee', etherType: '8864'}},
        {id: 'pppoe-sess', data: {version: 1, type: 1, code: 0, sessionId: 1, pppProtocol: 'c021', payload: '01010008010405dc'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'pppoe-sess'])
    const pppoe: any = Layer(decoded, 'pppoe-sess').data
    assert.strictEqual(pppoe.length, 10, 'auto-computed Length = 2 (protocol) + 8 (payload)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted frame supplies an explicit (lying) Length — honored verbatim.
test('PPPoE honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '00:aa:bb:cc:dd:ee', etherType: '8864'}},
        {id: 'pppoe-sess', data: {version: 1, type: 1, code: 0, sessionId: 0x0abc, length: 4, pppProtocol: '0021', payload: '45'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const pppoe: any = Layer(decoded, 'pppoe-sess').data
    assert.strictEqual(pppoe.sessionId, 0x0abc, 'session id honored')
    assert.strictEqual(pppoe.length, 4, 'supplied (lying) Length honored, not derived')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a non-0x8864 ethertype must NOT be claimed as PPPoE; and a truncated PPPoE frame must
// survive decode without throwing.
test('PPPoE is not claimed on a foreign ethertype, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '00:aa:bb:cc:dd:ee', etherType: '88b5'}},
        {id: 'raw', data: {data: '1100000100 0ac02101010008010405dc'.replace(/\s/g, '')}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'pppoe-sess'), 'foreign ethertype must not be claimed as PPPoE')

    // Slice mid-PPP-payload (25 of 30 bytes): the PPPoE layer must still decode, clamping its
    // Length-bounded payload to the captured bytes, without throwing.
    const full: Buffer = LoadPacket('pppoe/session-lcp').buffer
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, 25))
    assert.ok(survived.some((l: CodecDecodeResult): boolean => l.id === 'pppoe-sess'), 'truncated PPPoE still decodes')
})
