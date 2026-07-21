import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// The Called/Calling encoded NetBIOS names of the session_request fixture (called=FRED<20> calling=BARNEY<00>).
const SR_PAYLOAD: string = '2045474643454645454341434143414341434143414341434143414341434143410020454345424643454f4546464a434143414341434143414341434143414341414100'

// NBSS (tcp:139) Session Request — 4-byte header (type + flags + 16-bit length) + encoded NetBIOS names.
test('NBSS Session Request: header + payload + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('nbss/session_request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'nbss'])
    const nbss: any = Layer(decoded, 'nbss').data
    assert.strictEqual(nbss.type, 0x81, 'Session Request')
    assert.strictEqual(nbss.flags, 0, 'reserved flags / E bit clear')
    assert.strictEqual(nbss.length, 68, 'two 34-byte encoded names')
    assert.strictEqual(nbss.payload, SR_PAYLOAD, 'Called + Calling encoded NetBIOS names, verbatim')
})

// A Session Message (type 0x00) carrying an SMB payload — the payload is kept verbatim and bounded by
// the header length, and must reproduce byte-for-byte.
test('NBSS Session Message: SMB payload kept verbatim + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('nbss/session_message').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'nbss'])
    const nbss: any = Layer(decoded, 'nbss').data
    assert.strictEqual(nbss.type, 0x00, 'Session Message')
    assert.strictEqual(nbss.length, 35, 'SMB1 header byte count')
    assert.ok(nbss.payload.startsWith('ff534d42'), 'payload is an SMB message (\\xffSMB)')
})

// Crafting: a Session Keep Alive (type 0x85, empty payload) with the Length auto-computed from the
// (empty) payload — the minimal well-formed NBSS PDU must re-encode byte-identically.
test('NBSS faithfully encodes a crafted Keep Alive and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.2', dip: '192.0.2.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 139}},
        {id: 'nbss', data: {type: 0x85}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'nbss'])
    const nbss: any = Layer(decoded, 'nbss').data
    assert.strictEqual(nbss.type, 0x85, 'Keep Alive')
    assert.strictEqual(nbss.length, 0, 'auto-computed Length = 0 (empty payload)')
    assert.strictEqual(nbss.payload, '', 'empty payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted Session Message supplies an explicit Length — it must be honored
// verbatim (not overwritten by the derived value) so a PDU that carries any Length round-trips.
test('NBSS honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 139, dstport: 51000}},
        // Length lies (says 2) but 4 payload bytes are present — the supplied Length is honored on the wire.
        {id: 'nbss', data: {type: 0x00, flags: 0, length: 2, payload: 'deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const nbss: any = Layer(decoded, 'nbss').data
    assert.strictEqual(nbss.type, 0x00, 'Session Message')
    assert.strictEqual(nbss.length, 2, 'supplied Length honored (not derived to 4)')
    // The header bounds consumption to Length=2, so only the first 2 payload bytes are this PDU's; the
    // trailing 2 bytes fall through to raw.
    assert.strictEqual(nbss.payload, 'dead', 'payload bounded by the (lying) Length')
    assert.strictEqual(Layer(decoded, 'raw').data.data, 'beef', 'bytes past Length left to raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/139 payload whose first byte is not a valid NBSS type must NOT be claimed as NBSS
// (falls through to raw); and a truncated NBSS PDU must survive decode without throwing.
test('NBSS rejects an invalid type on port 139, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 139}},
        // 0x42 is not a NetBIOS Session Service type
        {id: 'raw', data: {data: '42000004deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'nbss'), 'invalid type must not be claimed as NBSS')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('nbss/session_request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 40))
})

// Protocol-specific edge: two NBSS PDUs pipelined in one TCP segment. The first is bounded by its Length,
// so its payload does NOT swallow the trailing PDU; the trailing bytes fall through to raw (a leaf header
// advances only over its own PDU and does not re-match itself). Both directions round-trip byte-for-byte.
test('NBSS pipelining: the first PDU is bounded by its Length; the trailing PDU falls through to raw', async (): Promise<void> => {
    const first: string = '00000004deadbeef'   // Session Message, length 4, 4-byte payload => 8 bytes
    const second: string = '85000000'          // Session Keep Alive => 4 bytes
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 139, dstport: 51000}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'nbss', 'raw'])
    const nbss: any = Layer(decoded, 'nbss').data
    assert.strictEqual(nbss.type, 0x00, 'first is a Session Message')
    assert.strictEqual(nbss.payload, 'deadbeef', 'payload bounded by its Length — trailing PDU not swallowed')
    assert.strictEqual(Layer(decoded, 'raw').data.data, second, 'trailing Keep Alive left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
