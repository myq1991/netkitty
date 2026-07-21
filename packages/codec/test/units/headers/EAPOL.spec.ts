import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// A real-shaped EAPOL-Key frame (IEEE 802.1X, EtherType 0x888E): the WPA/RSN 4-way-handshake message 1
// (Packet Type 3), Version 2, a 95-byte 802.11 RSN key descriptor body. 113 bytes total, no padding.
// Byte-perfect round-trip + the fixed header fields decode as expected.
test('EAPOL EAPOL-Key: fixed header decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('eapol/key-m1').buffer)
    AssertLayers(decoded, ['eth', 'eapol'])
    const eapol: any = Layer(decoded, 'eapol').data
    assert.strictEqual(eapol.version, 2, 'Version 2 (802.1X-2004)')
    assert.strictEqual(eapol.packetType, 3, 'Packet Type 3 = EAPOL-Key')
    assert.strictEqual(eapol.bodyLength, 95, 'Body Length = the 95-byte RSN key descriptor')
    assert.strictEqual(eapol.body.length / 2, 95, 'body kept verbatim, exactly Body Length bytes')
    assert.ok(eapol.body.startsWith('02008a0010'), 'body begins with Descriptor Type 02 + Key Info 008a + Key Length 0010')
})

// Craft an EAPOL-Start (Packet Type 1, empty body) from scratch and require a byte-perfect
// encode → decode → re-encode round-trip. Start/Logoff carry no body (Body Length 0).
test('EAPOL crafted EAPOL-Start: encode → decode → re-encode is byte-identical', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:03', smac: '00:0c:29:33:cc:dd', etherType: '888e'}},
        {id: 'eapol', data: {version: 2, packetType: 1, body: ''}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'eapol'])
    const eapol: any = Layer(decoded, 'eapol').data
    assert.strictEqual(eapol.packetType, 1, 'EAPOL-Start')
    assert.strictEqual(eapol.bodyLength, 0, 'empty body → Body Length 0')
    assert.strictEqual(eapol.body, '', 'no body bytes')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// Body Length is honor-else-derive: omit it on encode and it must be derived from the body byte count;
// supply it explicitly (even a value shorter than the body) and it must be honored verbatim, with the
// bytes beyond it left to the codec's recursion (RawData) rather than swallowed.
test('EAPOL Body Length: derived when omitted, honored (and bounds the body) when supplied', async (): Promise<void> => {
    // Derived: an EAP-Packet (type 0) carrying a 5-byte EAP Request/Identity, no bodyLength provided.
    const derived: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:03', smac: '00:0c:29:33:cc:dd', etherType: '888e'}},
        {id: 'eapol', data: {version: 1, packetType: 0, body: '0101000501'}}
    ])
    // Header bytes at offset 14: version=01 type=00 bodyLength=0005 (derived from the 5 body bytes).
    assert.strictEqual(derived.packet.subarray(14, 18).toString('hex'), '01000005', 'Body Length derived from body byte count')
    const decodedDerived: CodecDecodeResult[] = await codec.decode(derived.packet)
    AssertLayers(decodedDerived, ['eth', 'eapol'])
    assert.strictEqual(Layer(decodedDerived, 'eapol').data.bodyLength, 5)

    // Honored: an explicit Body Length of 2 (a crafted lie) truncates the claimed body to 2 bytes; the
    // remaining 3 body bytes fall out of the header and become a trailing Raw layer. Still byte-perfect.
    const honored: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:03', smac: '00:0c:29:33:cc:dd', etherType: '888e'}},
        {id: 'eapol', data: {version: 1, packetType: 0, bodyLength: 2, body: '0101000501'}}
    ])
    const decodedHonored: CodecDecodeResult[] = await codec.decode(honored.packet)
    AssertLayers(decodedHonored, ['eth', 'eapol', 'raw'])
    const eapol: any = Layer(decodedHonored, 'eapol').data
    assert.strictEqual(eapol.bodyLength, 2, 'crafted Body Length honored verbatim')
    assert.strictEqual(eapol.body.length / 2, 2, 'body bounded to the honored Body Length')
    assert.strictEqual((await codec.encode(decodedHonored)).packet.toString('hex'), honored.packet.toString('hex'))
})

// Negative: EAPOL is an Ethernet child gated on EtherType 0x888E. A frame on a different EtherType (an
// ARP frame, 0x0806) must NOT be claimed as EAPOL. And a frame truncated to fewer than the 4-byte fixed
// header must not be claimed either (match requires the full header) — decode must still survive.
test('EAPOL negative: non-888E frame not claimed + sub-header truncation survives', async (): Promise<void> => {
    // A well-formed ARP request (EtherType 0x0806) — decodes as eth/arp, never eapol.
    const arp: Buffer = Buffer.from('ffffffffffff00112233445508060001080006040001001122334455c0a80101000000000000c0a80102', 'hex')
    const arpDecoded: CodecDecodeResult[] = await codec.decode(arp)
    assert.ok(!arpDecoded.some((l: CodecDecodeResult): boolean => l.id === 'eapol'), 'a non-888E frame must not be claimed as EAPOL')

    // Cut the EAPOL-Key fixture to 16 bytes: 14 eth + only 2 of the 4 header bytes. match() requires the
    // full 4-byte header, so EAPOL declines and the bytes fall through to Raw. Decode survives + round-trips.
    const truncated: Buffer = LoadPacket('eapol/key-m1').buffer.subarray(0, 16)
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(truncated)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'eapol'), 'an incomplete header must not be claimed as EAPOL')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), truncated.toString('hex'), 'truncated frame round-trips via Raw')
})

// Protocol-specific edge: a body truncated mid-descriptor (Body Length claims more than the captured
// bytes) must clamp the body to what is present (never read past the buffer) and still round-trip; and
// trailing bytes after a complete zero-length body (Ethernet padding / a pipelined frame) become Raw.
test('EAPOL edge: truncated body clamps to available; trailing bytes become Raw', async (): Promise<void> => {
    // Body Length says 95 but only 30 - 18 = 12 body bytes are present: the body clamps to 12, decode survives.
    const truncatedBody: Buffer = LoadPacket('eapol/key-m1').buffer.subarray(0, 30)
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(truncatedBody)
    AssertLayers(decoded, ['eth', 'eapol'])
    const eapol: any = Layer(decoded, 'eapol').data
    assert.strictEqual(eapol.bodyLength, 95, 'the claimed Body Length is preserved verbatim')
    assert.strictEqual(eapol.body.length / 2, 12, 'the body is clamped to the captured bytes, not read past the buffer')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), truncatedBody.toString('hex'), 'the truncated frame round-trips')

    // A complete EAPOL-Logoff (empty body) followed by 6 trailing bytes: the trailing bytes are outside
    // the (zero-length) body and surface as a Raw layer, preserving the frame exactly.
    const logoff: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:03', smac: '00:0c:29:33:cc:dd', etherType: '888e'}},
        {id: 'eapol', data: {version: 2, packetType: 2, body: ''}}
    ])
    const withTrailing: Buffer = Buffer.concat([logoff.packet, Buffer.from('deadbeefcafe', 'hex')])
    const trailingDecoded: CodecDecodeResult[] = await AssertRoundTrip(withTrailing)
    AssertLayers(trailingDecoded, ['eth', 'eapol', 'raw'])
    assert.strictEqual(Layer(trailingDecoded, 'eapol').data.packetType, 2, 'EAPOL-Logoff')
})
