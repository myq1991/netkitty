import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// STARTUP body: CQL [string map] {"CQL_VERSION":"3.0.0"} — n=1, key len 11 "CQL_VERSION", value len 5 "3.0.0".
const STARTUP_BODY: string = '0001000b43514c5f56455253494f4e0005332e302e30'

// Cassandra CQL native protocol v4 (tcp:9042) STARTUP — 9-byte frame header (version/flags/stream/opcode/
// length) + body, byte-perfect round-trip.
test('CQL STARTUP: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('cql/startup').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'cql'])
    const cql: any = Layer(decoded, 'cql').data
    assert.strictEqual(cql.version, 0x04, 'v4 request (direction bit 0)')
    assert.strictEqual(cql.flags, 0, 'no flags')
    assert.strictEqual(cql.stream, 1, 'stream id 1')
    assert.strictEqual(cql.opcode, 1, 'STARTUP')
    assert.strictEqual(cql.length, 22, 'body length')
    assert.strictEqual(cql.body, STARTUP_BODY, 'string map {"CQL_VERSION":"3.0.0"}')
})

// Crafting: an OPTIONS (opcode 5, empty body) with the Length auto-computed from the (empty) body — the
// minimal well-formed CQL frame must re-encode byte-identically.
test('CQL faithfully encodes a crafted OPTIONS and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 9042}},
        {id: 'cql', data: {version: 0x04, opcode: 5}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'cql'])
    const cql: any = Layer(decoded, 'cql').data
    assert.strictEqual(cql.opcode, 5, 'OPTIONS')
    assert.strictEqual(cql.length, 0, 'auto-computed Length = 0 (empty body)')
    assert.strictEqual(cql.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted QUERY supplies an explicit Length — it must be honored verbatim
// (not overwritten by the derived value) so a frame that carries any Length round-trips.
test('CQL honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    // QUERY (opcode 7) body: [long string] "SELECT" (len 6) — 4-byte length prefix + 6 bytes = 10 bytes.
    const queryBody: string = '00000006' + '53454c454354'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.20', dip: '192.0.2.10', protocol: 6}},
        {id: 'tcp', data: {srcport: 9042, dstport: 51000}},
        {id: 'cql', data: {version: 0x84, stream: 7, opcode: 7, length: 10, body: queryBody}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const cql: any = Layer(decoded, 'cql').data
    assert.strictEqual(cql.version, 0x84, 'v4 response (direction bit set)')
    assert.strictEqual(cql.opcode, 7, 'QUERY')
    assert.strictEqual(cql.length, 10, 'supplied Length honored')
    assert.strictEqual(cql.body, queryBody, 'query body verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: garbage on TCP/9042 (an out-of-range version 0xff and an unknown opcode 0x42) must still
// decode without throwing and must re-encode byte-for-byte (line values are clamped, never rejected);
// and a truncated STARTUP frame must survive decode without throwing.
test('CQL survives garbage on port 9042 and truncation', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 9042}},
        // version 0xff, flags 0x00, stream 0xabcd, opcode 0x42, length 4, body 'deadbeef' (no registered magic)
        {id: 'raw', data: {data: 'ff00abcd4200000004deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const cql: any = Layer(decoded, 'cql').data
    assert.strictEqual(cql.version, 0xff, 'out-of-range version octet preserved')
    assert.strictEqual(cql.opcode, 0x42, 'unknown opcode preserved (no hard enum)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'garbage re-encodes byte-perfect')

    const full: Buffer = LoadPacket('cql/startup').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})

// Protocol-specific edge: two CQL frames pipelined in one TCP segment. The first frame is bounded by its
// Length, so its body does NOT swallow the trailing frame; the trailing bytes fall through to raw (a leaf
// header advances only over its own frame). Both directions round-trip byte-for-byte.
test('CQL pipelining: the first frame is bounded by its Length; the trailing frame falls through to raw', async (): Promise<void> => {
    const first: string = '040000010100000016' + STARTUP_BODY   // 9-byte header + 22-byte STARTUP body
    const second: string = '040000020200000000'                 // bare 9-byte READY (opcode 2, empty body)
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 9042}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'cql', 'raw'])
    const cql: any = Layer(decoded, 'cql').data
    assert.strictEqual(cql.opcode, 1, 'first is STARTUP')
    assert.strictEqual(cql.body, STARTUP_BODY, 'STARTUP body bounded by its Length — trailing frame not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing READY left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
