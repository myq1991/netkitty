import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Real-shape Ident query (RFC 1413) on TCP port 113: the client sends "6193, 23\r\n" — the server-side
// TCP port 6193 and the client-side TCP port 23, terminated by CR LF. The whole payload is kept verbatim
// (byte-perfect); the first line is parsed into display-only metadata {isQuery, serverPort, clientPort}.
test('Ident query: two ports, byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ident/query').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'ident'])
    const ident: any = Layer(decoded, 'ident').data
    assert.strictEqual(ident.isQuery, true, 'a query carries only the two ports')
    assert.strictEqual(ident.serverPort, 6193, 'server-side TCP port')
    assert.strictEqual(ident.clientPort, 23, 'client-side TCP port')
    assert.strictEqual(ident.responseType, '', 'a query has no reply type')
    assert.strictEqual(ident.message, '363139332c2032330d0a', 'message holds the whole payload verbatim')
})

// Real-shape Ident USERID reply on TCP port 113: the server answers "6193, 23 : USERID : UNIX : stjohns\r\n"
// — the same ports, reply type USERID, the opsys token, and the owning user name. Kept verbatim; the
// first line is parsed into {responseType, opsys, userId}.
test('Ident USERID reply: byte-perfect round-trip and parsed opsys/user', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ident/userid').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'ident'])
    const ident: any = Layer(decoded, 'ident').data
    assert.strictEqual(ident.isQuery, false, 'a reply has the ":" USERID/ERROR structure')
    assert.strictEqual(ident.responseType, 'USERID', 'successful reply type')
    assert.strictEqual(ident.serverPort, 6193, 'server-side port echoed')
    assert.strictEqual(ident.clientPort, 23, 'client-side port echoed')
    assert.strictEqual(ident.opsys, 'UNIX', 'operating-system token')
    assert.strictEqual(ident.userId, 'stjohns', 'owning user name')
})

// Crafted ERROR reply: "113, 6193 : ERROR : NO-USER\r\n". A verbatim message is kept as the source of
// truth and round-trips byte-for-byte; the metadata report the ERROR reply type and its error-type.
test('Ident faithfully encodes a crafted ERROR reply (verbatim)', async (): Promise<void> => {
    const payload: string = Buffer.from('113, 6193 : ERROR : NO-USER\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.2', dip: '192.0.2.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 113, dstport: 40000}},
        {id: 'ident', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'ident'])
    const ident: any = Layer(decoded, 'ident').data
    assert.strictEqual(ident.isQuery, false, 'an ERROR line is a reply')
    assert.strictEqual(ident.responseType, 'ERROR', 'failure reply type')
    assert.strictEqual(ident.errorType, 'NO-USER', 'the error-type token')
    assert.strictEqual(ident.serverPort, 113, 'first port parsed')
    assert.strictEqual(ident.clientPort, 6193, 'second port parsed')
    assert.strictEqual(ident.message, payload, 'the byte stream is kept verbatim')
})

// Port confinement (no heuristicFallback): an Ident-looking line on a non-113 port must NOT be claimed as
// Ident — it falls through to raw. And a truncated payload on port 113 must decode without throwing and
// remain re-encodable.
test('Ident is confined to port 113; truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 49798, dstport: 9999}}, // not port 113
        {id: 'raw', data: {data: Buffer.from('6193, 23\r\n', 'latin1').toString('hex')}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'ident'), 'Ident text off port 113 must not be claimed')

    // A reply cut mid-line on port 113 must decode without throwing and stay re-encodable.
    const full: Buffer = LoadPacket('ident/userid').buffer
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 8))
    await codec.encode(survived)
})

// Protocol edge: a payload with NO line terminator still parses (the whole payload is the line), and a
// malformed line with non-numeric ports is kept verbatim without throwing — the ports clamp to 0.
test('Ident parses a terminator-less line and malformed ports without throwing', async (): Promise<void> => {
    const noEol: string = Buffer.from('6193, 23 : USERID : UNIX : root', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 113, dstport: 55000}},
        {id: 'ident', data: {message: noEol}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const ident: any = Layer(decoded, 'ident').data
    assert.strictEqual(ident.userId, 'root', 'a line with no CR LF is still parsed')
    assert.strictEqual(ident.message, noEol, 'kept verbatim with no terminator')

    // Malformed: non-numeric ports must not throw; they clamp to 0 and the bytes still round-trip.
    const bad: string = Buffer.from('abc, xyz\r\n', 'latin1').toString('hex')
    const {packet: packet2}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 113, dstport: 55000}},
        {id: 'ident', data: {message: bad}}
    ])
    const decoded2: CodecDecodeResult[] = await AssertRoundTrip(packet2)
    const ident2: any = Layer(decoded2, 'ident').data
    assert.strictEqual(ident2.serverPort, 0, 'non-numeric server port clamps to 0')
    assert.strictEqual(ident2.clientPort, 0, 'non-numeric client port clamps to 0')
    assert.strictEqual(ident2.message, bad, 'malformed line kept verbatim')
})
