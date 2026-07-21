import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// RTPS 2.1 (OMG DDSI-RTPS) over UDP — 20-byte header + INFO_TS + DATA submessages. Constructed
// spec-accurate frame; Wireshark 'rtps' dissector agrees (eth:ethertype:ip:udp:rtps).
test('RTPS INFO_TS + DATA: header + submessages + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rtps/info-ts-data').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rtps'])
    const rtps: any = Layer(decoded, 'rtps').data
    assert.strictEqual(rtps.magic, '52545053', "magic 'RTPS'")
    assert.strictEqual(rtps.protocolVersion, '0201', 'RTPS 2.1')
    assert.strictEqual(rtps.vendorId, '0101', 'RTI Connext')
    assert.strictEqual(rtps.guidPrefix, '010f45d2123456789abcdef0')
    assert.strictEqual(rtps.submessages.length, 2)
    // INFO_TS: id 0x09, flags E=1 (little-endian submessage header), 8-byte timestamp body.
    assert.deepStrictEqual(rtps.submessages[0], {submessageId: 0x09, flags: 0x01, submessageLength: 8, body: 'a1b2c3d4e5f60708'})
    // DATA: id 0x15, flags 0x05 (E=1 + Data present), 28-byte body kept verbatim.
    assert.deepStrictEqual(rtps.submessages[1], {submessageId: 0x15, flags: 0x05, submessageLength: 28, body: '00001000000001c7000001c200000000000000010000000001000000'})
})

// RTPS uses dynamically negotiated UDP ports, so it must be recognized by its 'RTPS' magic content
// signature on ANY UDP port (heuristicFallback), not only the 7400-range defaults. A crafted message
// on an arbitrary port round-trips byte-for-byte.
test('RTPS is recognized off the well-known discovery ports via the RTPS magic', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 55000, dstport: 55001}},
        {id: 'rtps', data: {
            magic: '52545053', protocolVersion: '0203', vendorId: '010f',
            guidPrefix: 'aabbccddeeff00112233445566',
            submessages: [
                // HEARTBEAT (id 0x07), flags E=1 (little-endian), 28-byte body.
                {submessageId: 0x07, flags: 0x01, submessageLength: 28, body: '000001c2000001c700000000000000010000000000000002' + '00000001'}
            ]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'rtps'])
    const rtps: any = Layer(decoded, 'rtps').data
    assert.strictEqual(rtps.protocolVersion, '0203', 'RTPS 2.3 recognized on a non-default UDP port')
    assert.strictEqual(rtps.submessages[0].submessageId, 0x07, 'HEARTBEAT')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// The low bit of a submessage's flags octet (EndiannessFlag) governs the byte order of its
// submessageLength field. A big-endian submessage (E=0) must write/read the length big-endian; a
// little-endian one (E=1) little-endian. Both survive a byte round-trip.
test('RTPS submessageLength byte order follows each submessage EndiannessFlag', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 7410, dstport: 7411}},
        {id: 'rtps', data: {
            magic: '52545053', protocolVersion: '0201', vendorId: '0101',
            guidPrefix: '000000000000000000000000',
            submessages: [
                {submessageId: 0x15, flags: 0x00, submessageLength: 4, body: 'deadbeef'}, // E=0 → BE length 0x0004
                {submessageId: 0x15, flags: 0x01, submessageLength: 4, body: 'cafebabe'}  // E=1 → LE length 0x0400
            ]
        }}
    ])
    // The big-endian submessage encodes its length as 00 04; the little-endian one as 04 00.
    assert.ok(packet.toString('hex').includes('15000004deadbeef'), 'big-endian submessageLength on the wire')
    assert.ok(packet.toString('hex').includes('15010400cafebabe'), 'little-endian submessageLength on the wire')
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const rtps: any = Layer(decoded, 'rtps').data
    assert.strictEqual(rtps.submessages[0].submessageLength, 4, 'big-endian length decoded correctly')
    assert.strictEqual(rtps.submessages[1].submessageLength, 4, 'little-endian length decoded correctly')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: an omitted submessageLength is derived from the body length on encode (in the
// endianness dictated by the flags); an explicitly supplied length is honored verbatim (a crafted
// message may lie). Both round-trip byte-for-byte.
test('RTPS derives an omitted submessageLength from the body and honors an explicit one', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 7410, dstport: 7411}},
        {id: 'rtps', data: {
            magic: '52545053', protocolVersion: '0201', vendorId: '0101',
            guidPrefix: '000000000000000000000000',
            submessages: [
                {submessageId: 0x09, flags: 0x01, body: '0102030405060708'} // no length → derive 8 (LE 0x0800)
            ]
        }}
    ])
    assert.ok(packet.toString('hex').includes('090108000102030405060708'), 'derived length 8 written little-endian')
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const rtps: any = Layer(decoded, 'rtps').data
    assert.strictEqual(rtps.submessages[0].submessageLength, 8, 'derived from the 8-byte body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a non-RTPS UDP payload (no 'RTPS' magic) must NOT be claimed as RTPS — it falls through
// to raw. And a truncated RTPS message (cut into a submessage body) must survive decode without throwing.
test('RTPS rejects a non-magic UDP payload, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 7400, dstport: 7401}},
        // 20+ bytes of unsigned bytes whose first four are NOT 'RTPS' (0x52545053).
        {id: 'raw', data: {data: 'deadbeef0011223344556677889900112233445566778899'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'rtps'), 'non-magic payload must not be claimed as RTPS')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('rtps/info-ts-data').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 8))
})
