import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// CAPWAP (RFC 5415, udp:5246 control) Discovery Request — 8-byte bit-packed header (preamble + HLEN/RID/
// WBID/flags/fragment) delimiting the header by HLEN, then the control-plane payload kept verbatim.
test('CAPWAP Discovery Request: preamble + bit-packed header + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('capwap/discovery-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'capwap'])
    const capwap: any = Layer(decoded, 'capwap').data
    assert.strictEqual(capwap.version, 0, 'Version 0')
    assert.strictEqual(capwap.type, 0, 'Type 0 = CAPWAP header (not DTLS)')
    assert.strictEqual(capwap.hlen, 2, 'HLEN = 2 (8-byte header, no optional fields)')
    assert.strictEqual(capwap.rid, 1, 'Radio ID 1')
    assert.strictEqual(capwap.wbid, 1, 'Wireless Binding ID 1 (IEEE 802.11)')
    assert.strictEqual(capwap.flags.m, false, 'M flag clear (no Radio MAC)')
    assert.strictEqual(capwap.flags.w, false, 'W flag clear (no Wireless Specific Info)')
    assert.strictEqual(capwap.fragmentId, 0, 'Fragment ID 0')
    assert.strictEqual(capwap.fragmentOffset, 0, 'Fragment Offset 0')
    assert.strictEqual(capwap.headerRemainder, '', 'no optional header fields')
    // Control Header (Discovery Request) + Discovery Type message element, kept verbatim.
    assert.strictEqual(capwap.payload, '00000001000008000014000100', 'control-plane payload verbatim')
})

// Crafting: a minimal control header with HLEN auto-derived from the (empty) optional header — HLEN must
// come out 2 (the 8-byte fixed header) and the message must re-encode byte-identically.
test('CAPWAP auto-derives HLEN from the header bytes when not supplied', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 20000, dstport: 5246}},
        {id: 'capwap', data: {version: 0, type: 0, rid: 1, wbid: 1, payload: 'deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'capwap'])
    const capwap: any = Layer(decoded, 'capwap').data
    assert.strictEqual(capwap.hlen, 2, 'auto-derived HLEN = 2 (8-byte header, empty remainder)')
    assert.strictEqual(capwap.payload, 'deadbeef', 'payload preserved')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive HLEN: an explicit HLEN is honored verbatim (not overwritten by the derived value),
// so a header that carries any HLEN round-trips. HLEN=4 with an empty optional header would derive to 2.
test('CAPWAP honors an explicitly supplied HLEN (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 20000, dstport: 5246}},
        {id: 'capwap', data: {version: 0, type: 0, rid: 1, wbid: 1, hlen: 4, payload: 'aabbccdd'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const capwap: any = Layer(decoded, 'capwap').data
    assert.strictEqual(capwap.hlen, 4, 'supplied HLEN honored (would derive to 2)')
    assert.strictEqual(capwap.payload, 'aabbccdd', 'payload bounded by HLEN x 4')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Optional per-flag header: M flag set + a 4-byte Radio-MAC-shaped optional field kept verbatim as
// headerRemainder; HLEN auto-derives to 3 (12-byte header) and the whole thing round-trips.
test('CAPWAP carries the optional header verbatim and derives HLEN to cover it', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 20000, dstport: 5247}},
        {id: 'capwap', data: {version: 0, type: 0, rid: 2, wbid: 1, flags: {m: true}, headerRemainder: '11223344', payload: 'cafe'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const capwap: any = Layer(decoded, 'capwap').data
    assert.strictEqual(capwap.flags.m, true, 'M flag set')
    assert.strictEqual(capwap.hlen, 3, 'auto-derived HLEN = 3 (8 fixed + 4 optional)')
    assert.strictEqual(capwap.headerRemainder, '11223344', 'optional header kept verbatim')
    assert.strictEqual(capwap.payload, 'cafe', 'payload after the optional header')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a sub-8-byte UDP payload on port 5246 must NOT be claimed as CAPWAP (the min-length guard
// makes it fall through to raw); and a truncated CAPWAP message must survive decode without throwing.
test('CAPWAP rejects a too-short payload on port 5246, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 20000, dstport: 5246}},
        {id: 'raw', data: {data: '01020304'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'capwap'), 'sub-8-byte payload must not be claimed as CAPWAP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('capwap/discovery-request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 5))
})
