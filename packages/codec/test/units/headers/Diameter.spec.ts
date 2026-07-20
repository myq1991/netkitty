import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Spec-accurate Diameter CER (Command Code 257, RFC 6733) on TCP 3868. 20-byte header + 5 AVPs whose
// alignment padding must survive a byte-perfect round-trip.
test('Diameter CER: header + AVP decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('diameter/cer').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'diameter'])
    const diameter: any = Layer(decoded, 'diameter').data
    assert.strictEqual(diameter.version, 1, 'Diameter version is always 1')
    assert.strictEqual(diameter.commandCode, 257, 'Capabilities-Exchange')
    assert.strictEqual(diameter.commandFlags, 0x80, 'R (Request) flag set')
    assert.strictEqual(diameter.messageLength, 116)
    // Origin-Host(264), Origin-Realm(296), Host-IP-Address(257), Vendor-Id(266), Product-Name(269).
    assert.deepStrictEqual(diameter.avps.map((a: any): number => a.code), [264, 296, 257, 266, 269])
    assert.strictEqual(diameter.avps[0].code, 264, 'first AVP is Origin-Host')
    assert.strictEqual(
        Buffer.from(diameter.avps[0].data, 'hex').toString('ascii'),
        'client.example.com',
        'Origin-Host value'
    )
    // The 18-byte Origin-Host needs 2 alignment bytes; they are preserved verbatim.
    assert.strictEqual(diameter.avps[0].padding, '0000', 'Origin-Host 2-byte alignment pad preserved')
})

// A vendor-specific AVP sets the V flag (0x80), which inserts a 4-byte Vendor-Id after the length. This
// proves the conditional Vendor-Id and the padding both round-trip: encode → decode → encode is exact.
test('Diameter vendor-specific AVP (V flag) carries a Vendor-Id and re-encodes byte-identically', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 3868}},
        {id: 'diameter', data: {
            version: 1, commandFlags: 0x80, commandCode: 257,
            applicationId: 0, hopByHopId: 1, endToEndId: 2,
            // V(0x80)+M(0x40) → headerSize 12, 5-byte data → avpLength 17 → 3 pad bytes.
            avps: [{code: 100, flags: 0xc0, vendorId: 10415, data: '0102030405'}]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'diameter'])
    const diameter: any = Layer(decoded, 'diameter').data
    assert.strictEqual(diameter.avps[0].flags, 0xc0, 'V+M flags')
    assert.strictEqual(diameter.avps[0].vendorId, 10415, 'Vendor-Id present because V is set')
    assert.strictEqual(diameter.avps[0].length, 17, 'AVP header(12) + data(5), excluding padding')
    assert.strictEqual(diameter.avps[0].padding, '000000', '17 % 4 → 3 alignment bytes')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// Message Length honor-else-derive, plus a data length that needs padding (5-byte data → 3 pad bytes).
// A raw-injected message carries an explicit Message Length (36) which must be honored verbatim, and its
// AVP's 3 trailing pad bytes must be preserved exactly.
test('Diameter honors an on-wire Message Length and preserves AVP padding', async (): Promise<void> => {
    // 01 msgLen=000024(36) flags=80 cmd=000101 appId=0 hbh=1 e2e=2 | AVP code=100 flags=40 len=00000d(13)
    // data=0102030405 (5 bytes) pad=000000 (3 bytes). 20 + 13 + 3 = 36.
    const diameterHex: string =
        '0100002480000101' + '000000000000000100000002' + '000000644000000d0102030405000000'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 3868}},
        {id: 'raw', data: {data: diameterHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const diameter: any = Layer(decoded, 'diameter').data
    assert.strictEqual(diameter.messageLength, 36, 'the on-wire Message Length is decoded as-is')
    assert.strictEqual(diameter.avps[0].length, 13, 'AVP length excludes padding')
    assert.strictEqual(diameter.avps[0].data, '0102030405')
    assert.strictEqual(diameter.avps[0].padding, '000000', '5-byte data → 3 alignment bytes preserved')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')

    // Derive path: crafting without a Message Length auto-computes it (20 header + 16 padded AVP = 36).
    const derived: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 3868}},
        {id: 'diameter', data: {
            version: 1, commandFlags: 0x80, commandCode: 257, applicationId: 0, hopByHopId: 1, endToEndId: 2,
            avps: [{code: 100, flags: 0x40, data: '0102030405'}]
        }}
    ])
    const derivedDiameter: any = Layer(await codec.decode(derived.packet), 'diameter').data
    assert.strictEqual(derivedDiameter.messageLength, 36, 'Message Length auto-computed from header + padded AVPs')
})

// A non-Diameter payload on port 3868 (Version 2, not 1) fails the content signature → falls to raw.
// And a truncated Diameter message must decode without throwing.
test('Diameter rejects a wrong-version payload on 3868 and survives truncation', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 3868}},
        // Version 2 + a plausible length, but Version != 1 → not Diameter.
        {id: 'raw', data: {data: '02' + '000018' + '00'.repeat(21)}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'diameter'), 'Version 2 is not Diameter')
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])

    const full: Buffer = LoadPacket('diameter/cer').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 10))
})

// An AVP without the V flag has no Vendor-Id (header size 8) — it must round-trip exactly and expose no
// vendorId field.
test('Diameter AVP without the V flag omits Vendor-Id and round-trips exactly', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 3868}},
        {id: 'diameter', data: {
            version: 1, commandFlags: 0x80, commandCode: 257, applicationId: 0, hopByHopId: 1, endToEndId: 2,
            // M only (0x40), no V → header size 8, no Vendor-Id. 4-byte data → no padding.
            avps: [{code: 296, flags: 0x40, data: 'aabbccdd'}]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const diameter: any = Layer(decoded, 'diameter').data
    assert.strictEqual(diameter.avps[0].length, 12, 'header(8) + data(4)')
    assert.strictEqual(diameter.avps[0].vendorId, undefined, 'no Vendor-Id without the V flag')
    assert.strictEqual(diameter.avps[0].padding, '', 'no padding needed (12 % 4 == 0)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})
