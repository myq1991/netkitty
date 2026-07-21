import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// A real PostgreSQL v3 simple Query ('Q') captured from psql → the postgres Docker container: frame the
// message (type + length + verbatim body) and reproduce the original bytes exactly.
test('PostgreSQL Query: typed frame + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('postgresql/query').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pgsql'])
    const pg: any = Layer(decoded, 'pgsql').data
    assert.strictEqual(pg.isStartup, false, 'a typed message is not a startup message')
    assert.strictEqual(pg.messageType, 'Q', 'Query message type byte')
    assert.strictEqual(pg.length, 14, 'length includes the 4 length bytes, not the type byte (body 10 + 4)')
    // body "SELECT 1;\0" = 10 bytes, verbatim
    assert.strictEqual(pg.body, '53454c45435420313b00', 'body is the query text kept verbatim')
})

// The startup message is the one exception with NO type byte: length(4) + protocol-version(4) + params.
// A crafted v3 StartupMessage must decode as a startup (offset 0 length, offset 4 body) and re-encode
// byte-identically — exercising the typed-vs-startup offset difference.
test('PostgreSQL StartupMessage: no type byte, protocol version in body, byte-identical re-encode', async (): Promise<void> => {
    const version: Buffer = Buffer.from('00030000', 'hex') // protocol v3.0
    const params: Buffer = Buffer.from('user\0postgres\0database\0postgres\0\0', 'latin1')
    const body: string = Buffer.concat([version, params]).toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 50000, dstport: 5432}},
        // messageType '' + isStartup ⇒ no type byte; length omitted ⇒ derived as 4 + body bytes.
        {id: 'pgsql', data: {isStartup: true, messageType: '', body}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pgsql'])
    const pg: any = Layer(decoded, 'pgsql').data
    assert.strictEqual(pg.isStartup, true, 'no type byte ⇒ startup message')
    assert.strictEqual(pg.messageType, '', 'a startup message has no type byte')
    assert.strictEqual(pg.length, 4 + Buffer.from(body, 'hex').length, 'derived length (includes its own 4 bytes)')
    assert.strictEqual(pg.body, body, 'body = protocol version + params, verbatim')
    assert.strictEqual(pg.body.slice(0, 8), '00030000', 'protocol version 3.0 leads the startup body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Length honor-else-derive + bounding: a typed message whose length is SHORTER than the captured payload
// must bound its body to (length − 4); the trailing bytes (here a non-PG tail) fall through to raw. The
// whole packet re-encodes byte-for-byte.
test('PostgreSQL bounds body by the length field; trailing bytes fall to raw', async (): Promise<void> => {
    // Payload: 'Q'(51) + length 8 (00000008) + 4-byte body 41424344 + 2 trailing non-PG bytes eeff.
    // length 8 ⇒ body = 8 − 4 = 4 bytes; the message ends at offset 1 + 8 = 9, leaving eeff to raw.
    const payload: string = '510000000841424344eeff'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 5432}},
        {id: 'raw', data: {data: payload}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pgsql', 'raw'])
    const pg: any = Layer(decoded, 'pgsql').data
    assert.strictEqual(pg.messageType, 'Q')
    assert.strictEqual(pg.length, 8, 'the shorter length is honored')
    assert.strictEqual(pg.body, '41424344', 'body bounded to length − 4, not the whole segment')
    assert.strictEqual(Layer(decoded, 'raw').data.data, 'eeff', 'the trailing bytes are left to raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Robustness + confinement: a truncated PG message survives decode; non-PG binary on 5432 is not claimed;
// and a PG-looking payload off the 5432 bucket (port 9999) is not claimed (port-confined, no heuristic).
test('PostgreSQL survives truncation and stays confined to its port bucket', async (): Promise<void> => {
    const full: Buffer = LoadPacket('postgresql/query').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 3))

    // Non-PG binary on port 5432: first byte 0xff is not a type letter and 0xff…​ is not a plausible
    // startup length ⇒ falls through to raw.
    const {packet: binary}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 5432}},
        {id: 'raw', data: {data: 'ff00ff00ff00'}}
    ])
    const binaryDecoded: CodecDecodeResult[] = await codec.decode(binary)
    assert.ok(!binaryDecoded.some((l: CodecDecodeResult): boolean => l.id === 'pgsql'), 'non-PG binary on 5432 must not be claimed')
    assert.strictEqual(binaryDecoded[binaryDecoded.length - 1].id, 'raw')

    // A perfectly valid-looking 'Q' message, but on port 9999 — outside the tcp:5432 bucket. Because
    // PostgreSQL has no heuristicFallback, it must not be recognized off-port.
    const {packet: offPort}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 9999}},
        {id: 'raw', data: {data: '510000000e53454c45435420313b00'}}
    ])
    const offPortDecoded: CodecDecodeResult[] = await codec.decode(offPort)
    assert.ok(!offPortDecoded.some((l: CodecDecodeResult): boolean => l.id === 'pgsql'), 'PG is port-confined; a Q-looking payload on 9999 stays raw')
    assert.strictEqual(offPortDecoded[offPortDecoded.length - 1].id, 'raw')
})

// A typed message with a non-trivial body (a 'C' CommandComplete tag) round-trips exactly, with the
// length auto-derived from the body on encode.
test('PostgreSQL typed message body round-trips exactly (CommandComplete)', async (): Promise<void> => {
    const body: string = Buffer.from('SELECT 1\0', 'latin1').toString('hex') // 9 bytes
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.2', dip: '10.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 5432, dstport: 40000}},
        // length omitted ⇒ derived as 4 + body bytes = 13.
        {id: 'pgsql', data: {messageType: 'C', body}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pgsql'])
    const pg: any = Layer(decoded, 'pgsql').data
    assert.strictEqual(pg.isStartup, false)
    assert.strictEqual(pg.messageType, 'C', 'CommandComplete')
    assert.strictEqual(pg.length, 13, 'auto-derived length (4 + 9 body bytes)')
    assert.strictEqual(pg.body, body, 'CommandComplete tag kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
