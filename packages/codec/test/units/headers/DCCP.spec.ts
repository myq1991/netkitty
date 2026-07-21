import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// DCCP-Request (ipproto:33) over IPv4 — fixed 9-byte prefix structured, remainder kept verbatim.
test('DCCP Request: header fields + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('dccp/request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'dccp'])
    const dccp: any = Layer(decoded, 'dccp').data
    assert.strictEqual(dccp.srcPort, 40000, 'source port')
    assert.strictEqual(dccp.dstPort, 5001, 'destination port')
    assert.strictEqual(dccp.dataOffset, 5, 'data offset = 5 words (20-byte header)')
    assert.strictEqual(dccp.ccval, 0, 'CCVal')
    assert.strictEqual(dccp.cscov, 0, 'CsCov (full coverage)')
    assert.strictEqual(dccp.type, 0, 'Request')
    assert.strictEqual(dccp.x, 1, 'extended sequence numbers')
    // headerOptions = reserved(1)=00 + seq(6)=000000000001 + service code(4)=00000000 => 11 bytes (bytes 9..20)
    assert.strictEqual(dccp.headerOptions, '0000000000000100000000', 'reserved + seq + service code kept verbatim')
    assert.strictEqual(dccp.payload, 'abcd', 'application data after the header')
})

// Crafting: a minimal DCCP-Close (type 6) with Data Offset auto-derived from the verbatim header
// remainder — the packet must re-encode byte-identically and the derived length must be correct.
test('DCCP faithfully encodes a crafted Close and auto-derives Data Offset', async (): Promise<void> => {
    // X=0 short header: reserved(1)+seq(3) = 4 bytes of headerOptions => header = 9 + 4 = 13 => ceil(13/4)=4 words
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 33}},
        {id: 'dccp', data: {srcPort: 5001, dstPort: 40000, ccval: 0, cscov: 0, checksum: 0, res: 0, type: 6, x: 0, headerOptions: '00000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'dccp'])
    const dccp: any = Layer(decoded, 'dccp').data
    assert.strictEqual(dccp.type, 6, 'Close')
    assert.strictEqual(dccp.dataOffset, 4, 'auto-derived Data Offset = ceil((9+4)/4) = 4 words')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Data Offset: a crafted datagram supplies an explicit Data Offset — it must be
// honored verbatim (not overwritten by the derived value) so a datagram that lies about it round-trips.
test('DCCP honors an explicitly supplied Data Offset (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 33}},
        {id: 'dccp', data: {srcPort: 5001, dstPort: 40000, ccval: 0, cscov: 0, checksum: 0, res: 0, type: 6, x: 0, dataOffset: 3, headerOptions: '000000', payload: 'cafe'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const dccp: any = Layer(decoded, 'dccp').data
    assert.strictEqual(dccp.dataOffset, 3, 'supplied Data Offset honored (12-byte header)')
    assert.strictEqual(dccp.payload, 'cafe', 'application data after Data Offset*4')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a truncated DCCP datagram must survive decode without throwing; and IP proto 33 with fewer
// than 12 bytes of payload must NOT be claimed as DCCP (falls through to raw).
test('DCCP truncation survives, and a too-short proto-33 payload is not claimed', async (): Promise<void> => {
    const full: Buffer = LoadPacket('dccp/request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
    await AssertDecodeSurvives(full.subarray(0, 20))

    // 8-byte payload under IP proto 33 — below the 12-byte generic-header floor.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 33}},
        {id: 'raw', data: {data: '9c40138905000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'dccp'), 'too-short proto-33 payload must not be claimed as DCCP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
})
