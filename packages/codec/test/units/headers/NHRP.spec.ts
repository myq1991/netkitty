import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// NHRP (ip proto 54, RFC 2332) Resolution Request — 20-byte Fixed Header + Mandatory Part, carried
// directly over IPv4. Byte-perfect decode→encode of the real frame.
test('NHRP Resolution Request: fixed header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('nhrp/resolution-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'nhrp'])
    const nhrp: any = Layer(decoded, 'nhrp').data
    assert.strictEqual(nhrp.afn, 1, 'AFN 1 (IPv4 NBMA)')
    assert.strictEqual(nhrp.protocolType, '0800', 'protocol type 0x0800 (IPv4)')
    assert.strictEqual(nhrp.protocolSnap, '0000000000', 'no SNAP')
    assert.strictEqual(nhrp.hopCount, 255, 'hop count')
    assert.strictEqual(nhrp.packetSize, 52, 'total NHRP packet length incl 20-byte fixed header')
    assert.strictEqual(nhrp.checksum, 0x881c, 'checksum honored verbatim')
    assert.strictEqual(nhrp.extensionOffset, 0, 'no extensions')
    assert.strictEqual(nhrp.opVersion, 1, 'version 1')
    assert.strictEqual(nhrp.opType, 1, 'Resolution Request')
    assert.strictEqual(nhrp.shtl, 4, 'source NBMA addr type/len 4')
    assert.strictEqual(nhrp.sstl, 0, 'no source NBMA subaddress')
    assert.strictEqual(nhrp.body, '04040000000000010a000001ac100001ac100002000000000000038400000000', 'mandatory part kept verbatim')
})

// Crafting: a Registration Request (op type 3) with an empty body — the minimal 20-byte NHRP packet.
// Packet Length is auto-derived from the (empty) body => 20, and must re-encode byte-identically.
test('NHRP faithfully encodes a crafted Registration Request and auto-derives the Packet Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 54}},
        {id: 'nhrp', data: {afn: 1, protocolType: '0800', hopCount: 255, opVersion: 1, opType: 3, shtl: 0, sstl: 0}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'nhrp'])
    const nhrp: any = Layer(decoded, 'nhrp').data
    assert.strictEqual(nhrp.opType, 3, 'Registration Request')
    assert.strictEqual(nhrp.packetSize, 20, 'auto-derived Packet Length = 20 (fixed header only, empty body)')
    assert.strictEqual(nhrp.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Packet Length: a crafted Resolution Reply supplies an explicit Packet Length — it
// must be honored verbatim (not overwritten by the derived value) so a packet carrying any length
// round-trips byte-for-byte.
test('NHRP honors an explicitly supplied Packet Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.2', dip: '10.0.0.1', protocol: 54}},
        {id: 'nhrp', data: {afn: 1, protocolType: '0800', hopCount: 255, packetSize: 24, opVersion: 1, opType: 2, shtl: 4, sstl: 0, body: 'deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const nhrp: any = Layer(decoded, 'nhrp').data
    assert.strictEqual(nhrp.opType, 2, 'Resolution Reply')
    assert.strictEqual(nhrp.packetSize, 24, 'supplied Packet Length honored')
    assert.strictEqual(nhrp.body, 'deadbeef', 'body bounded by the supplied Packet Length')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: an IP proto 54 payload shorter than the 20-byte Fixed Header must NOT be claimed as NHRP
// (falls through to raw); and a truncated NHRP packet must survive decode without throwing.
test('NHRP rejects a sub-header-length payload on proto 54, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 54}},
        // only 8 bytes of IP payload — less than the 20-byte NHRP fixed header
        {id: 'raw', data: {data: '00010800000000ff'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'nhrp'), 'sub-header-length payload must not be claimed as NHRP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('nhrp/resolution-request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 8))
})
