import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// RSVP (ipproto:46) PATH message — 8-byte common header + a sequence of Length/Class-Num/C-Type/data
// objects, RFC 2205. The real-frame fixture must decode into its four objects and round-trip byte-perfect.
test('RSVP PATH: common header + objects + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rsvp/path').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'rsvp'])
    const rsvp: any = Layer(decoded, 'rsvp').data
    assert.strictEqual(rsvp.version, 1, 'RFC 2205 version 1')
    assert.strictEqual(rsvp.flags, 0, 'no flags')
    assert.strictEqual(rsvp.msgType, 1, 'PATH')
    assert.strictEqual(rsvp.checksum, 0xb643, 'checksum honored verbatim')
    assert.strictEqual(rsvp.sendTTL, 64, 'send TTL')
    assert.strictEqual(rsvp.length, 52, 'RSVP message length incl 8-byte common header')
    assert.strictEqual(rsvp.objects.length, 4, 'SESSION, RSVP_HOP, TIME_VALUES, SENDER_TEMPLATE')
    assert.deepStrictEqual(rsvp.objects[0], {length: 12, classNum: 1, cType: 1, data: 'c000020111001388'}, 'SESSION')
    assert.deepStrictEqual(rsvp.objects[2], {length: 8, classNum: 5, cType: 1, data: '00007530'}, 'TIME_VALUES 30000ms')
    assert.strictEqual(rsvp.objects[3].classNum, 11, 'SENDER_TEMPLATE')
})

// Crafting: a PathTear (type 5) with no objects — the Length is auto-derived to the 8-byte common
// header. The minimal well-formed RSVP message must re-encode byte-identically.
test('RSVP faithfully encodes a crafted objectless PathTear and derives the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 46}},
        {id: 'rsvp', data: {msgType: 5, sendTTL: 30, checksum: 0, objects: []}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'rsvp'])
    const rsvp: any = Layer(decoded, 'rsvp').data
    assert.strictEqual(rsvp.msgType, 5, 'PathTear')
    assert.strictEqual(rsvp.length, 8, 'auto-derived Length = 8 (common header only, no objects)')
    assert.deepStrictEqual(rsvp.objects, [], 'no objects')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted Resv supplies an explicit RSVP Length that overstates the true
// message size — it must be honored verbatim (not overwritten by the derived value) and round-trip.
test('RSVP honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 46}},
        // one 12-byte object => true message length is 20, but we claim 60
        {id: 'rsvp', data: {msgType: 2, length: 60, checksum: 0, objects: [{classNum: 3, cType: 1, data: 'c000020200000001'}]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const rsvp: any = Layer(decoded, 'rsvp').data
    assert.strictEqual(rsvp.msgType, 2, 'Resv')
    assert.strictEqual(rsvp.length, 60, 'supplied Length honored, not derived (would be 20)')
    assert.strictEqual(rsvp.objects.length, 1, 'the single object still decoded, bounded by the IP payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a truncated RSVP message must survive decode without throwing; and an object whose Length
// field overruns the message must be bounded (data clamped to the IP payload) rather than reading past it.
test('RSVP survives truncation and bounds an overrunning object Length', async (): Promise<void> => {
    const full: Buffer = LoadPacket('rsvp/path').buffer
    for (let cut: number = full.length; cut >= 34; cut -= 3) {
        await AssertDecodeSurvives(full.subarray(0, cut))
    }

    // object claims Length 40 but only 4 bytes of contents are present — the data must clamp to the
    // real payload and the message must still round-trip byte-for-byte.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 46}},
        {id: 'rsvp', data: {msgType: 1, checksum: 0, objects: [{length: 40, classNum: 1, cType: 1, data: 'c0000201'}]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const rsvp: any = Layer(decoded, 'rsvp').data
    assert.strictEqual(rsvp.objects.length, 1, 'the overrunning object is still captured')
    assert.strictEqual(rsvp.objects[0].data, 'c0000201', 'contents clamped to the available payload, not read past it')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Regression (was a double-count / byte-perfect break): an object whose contents are empty (Length 4,
// header only) must be fully consumed by RSVP, not re-decoded as a trailing RawData layer and duplicated
// on re-encode. The object header bytes are peeked dryRun during the walk, so an empty trailing object
// otherwise fell outside the header's consumed range.
test('RSVP consumes an empty trailing object (Length 4) without double-counting it', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 46}},
        // a data-bearing SESSION object then an empty (Length-4, no contents) object at the tail
        {id: 'rsvp', data: {msgType: 1, checksum: 0, objects: [
            {classNum: 1, cType: 1, data: 'c000020111001388'},
            {classNum: 1, cType: 1, data: ''}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'rsvp'])   // no phantom trailing raw from the empty object
    const rsvp: any = Layer(decoded, 'rsvp').data
    assert.strictEqual(rsvp.objects.length, 2, 'both objects captured, including the empty tail object')
    assert.deepStrictEqual(rsvp.objects[1], {length: 4, classNum: 1, cType: 1, data: ''}, 'empty object: Length 4, no data')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect, not duplicated')
})

// Protocol-specific edge: an RSVP message shorter than its IP payload (trailing padding) must be bounded
// by its own Length — the padding falls through to raw and is not swallowed into the objects.
test('RSVP is bounded by its Length; trailing IP-payload bytes fall through to raw', async (): Promise<void> => {
    // A well-formed 8-byte objectless message (Length 8) followed by 8 trailing bytes inside the IP payload.
    const rsvpMessage: string = '1001000040000008'   // ver1 type1 cksum0 ttl64 rsvd0 len8
    const trailing: string = 'deadbeefcafef00d'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 46}},
        {id: 'raw', data: {data: rsvpMessage + trailing}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'rsvp', 'raw'])
    const rsvp: any = Layer(decoded, 'rsvp').data
    assert.strictEqual(rsvp.length, 8, 'message bounded to its 8-byte Length')
    assert.deepStrictEqual(rsvp.objects, [], 'trailing bytes not swallowed as an object')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, trailing, 'trailing bytes left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
