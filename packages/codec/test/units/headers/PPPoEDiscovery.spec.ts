import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// PPPoE Discovery PADI (EtherType 0x8863) — 6-byte header (ver/type + code + session + length) + tags.
test('PPPoED PADI: header + tags + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('pppoe-disc/padi').buffer)
    AssertLayers(decoded, ['eth', 'pppoe-disc'])
    const disc: any = Layer(decoded, 'pppoe-disc').data
    assert.strictEqual(disc.version, 1, 'PPPoE version 1')
    assert.strictEqual(disc.type, 1, 'PPPoE type 1')
    assert.strictEqual(disc.code, 0x09, 'PADI')
    assert.strictEqual(disc.sessionId, 0x0000, 'session unassigned during discovery')
    assert.strictEqual(disc.length, 12, 'payload length = 12 tag bytes')
    assert.strictEqual(disc.tags.length, 2, 'Service-Name + Host-Uniq')
    assert.strictEqual(disc.tags[0].type, 0x0101, 'Service-Name tag')
    assert.strictEqual(disc.tags[0].value, '', 'empty Service-Name (any service)')
    assert.strictEqual(disc.tags[1].type, 0x0103, 'Host-Uniq tag')
    assert.strictEqual(disc.tags[1].value, '12345678', 'Host-Uniq value')
    assert.strictEqual(disc.padding, '', 'no trailing padding')
})

// PADO (Offer) from the Access Concentrator — carries the AC-Name tag.
test('PPPoED PADO: AC-Name tag + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('pppoe-disc/pado').buffer)
    AssertLayers(decoded, ['eth', 'pppoe-disc'])
    const disc: any = Layer(decoded, 'pppoe-disc').data
    assert.strictEqual(disc.code, 0x07, 'PADO')
    assert.strictEqual(disc.length, 19, 'payload length = 19 tag bytes')
    assert.strictEqual(disc.tags[0].type, 0x0102, 'AC-Name tag')
    assert.strictEqual(disc.tags[0].value, '697370', 'AC-Name "isp"')
})

// Crafting: a PADT (Terminate) with no tags — the Length must be auto-derived to 0 from the (empty)
// tag list, and the minimal well-formed message must re-encode byte-identically.
test('PPPoED faithfully encodes a crafted PADT and auto-derives the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:aa:bb:cc:dd:ee', smac: '00:11:22:33:44:55', etherType: '8863'}},
        {id: 'pppoe-disc', data: {code: 0xa7, sessionId: 0x1234, tags: []}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'pppoe-disc'])
    const disc: any = Layer(decoded, 'pppoe-disc').data
    assert.strictEqual(disc.code, 0xa7, 'PADT')
    assert.strictEqual(disc.sessionId, 0x1234, 'session id honored')
    assert.strictEqual(disc.length, 0, 'auto-derived Length = 0 (no tags)')
    assert.strictEqual(disc.tags.length, 0, 'no tags')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted frame supplies an explicit Length smaller than the tag bytes
// actually present — it must be honored verbatim (not overwritten by the derived value), and it must
// bound this layer's consumption so the tag bytes beyond it fall to `padding`. Round-trips byte-for-byte.
test('PPPoED honors an explicit Length and bounds the tag walk by it', async (): Promise<void> => {
    // Two 4-byte tags (8 bytes total) but Length claims only 4 => only the first tag is consumed.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:aa:bb:cc:dd:ee', smac: '00:11:22:33:44:55', etherType: '8863'}},
        {id: 'pppoe-disc', data: {code: 0x09, length: 4, tags: [
            {type: 0x0101, value: ''},
            {type: 0x0104, value: 'deadbeef'}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const disc: any = Layer(decoded, 'pppoe-disc').data
    assert.strictEqual(disc.length, 4, 'supplied Length honored (not derived over)')
    assert.strictEqual(disc.tags.length, 1, 'only the first tag is within the bounded Length')
    assert.strictEqual(disc.tags[0].type, 0x0101, 'first tag consumed')
    assert.strictEqual(disc.padding, '01040004deadbeef', 'the second tag falls beyond Length into padding')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a truncated header (< 6 bytes of payload) must NOT be claimed as PPPoED (falls through to
// raw) and must survive; a mid-tag truncation is still claimed, survives without throwing, and — because
// every byte (header + tags + trailing) is kept verbatim — re-encodes byte-for-byte.
test('PPPoED rejects a sub-6-byte payload, and truncation survives byte-perfectly', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:aa:bb:cc:dd:ee', smac: '00:11:22:33:44:55', etherType: '8863'}},
        {id: 'raw', data: {data: '11090000'}}   // only 4 bytes — shorter than the 6-byte header
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'pppoe-disc'), 'sub-6-byte payload must not be claimed as PPPoED')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('pppoe-disc/padi').buffer
    const truncated: Buffer = full.subarray(0, full.length - 2)   // cut mid Host-Uniq tag
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(truncated)
    assert.strictEqual(survived[survived.length - 1].id, 'pppoe-disc', 'truncated frame still claimed as PPPoED')
    assert.strictEqual((await codec.encode(survived)).packet.toString('hex'), truncated.toString('hex'), 'truncation re-encodes byte-perfectly (verbatim capture)')
})

// Robustness: arbitrary garbage under EtherType 0x8863 (>= 6 bytes) is claimed as PPPoED, must not throw,
// and — since header fields, tags, and trailing bytes are all captured verbatim — round-trips exactly.
test('PPPoED survives garbage on EtherType 0x8863 and round-trips it', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:aa:bb:cc:dd:ee', smac: '00:11:22:33:44:55', etherType: '8863'}},
        {id: 'raw', data: {data: 'deadbeefcafeff13370001020304050607'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(decoded.some((l: CodecDecodeResult): boolean => l.id === 'pppoe-disc'), 'garbage on 8863 is claimed as PPPoED')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'garbage round-trips byte-perfectly')
})
