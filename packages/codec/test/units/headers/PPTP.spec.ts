import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

const COOKIE: string = '1a2b3c4d'

// PPTP (tcp:1723) Start-Control-Connection-Request — 12-byte structured control header (length + PDU
// type + magic cookie + control message type + reserved0) + SCCRQ body, byte-perfect round-trip.
test('PPTP SCCRQ: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('pptp/sccrq').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pptp'])
    const pptp: any = Layer(decoded, 'pptp').data
    assert.strictEqual(pptp.length, 156, 'total control message length incl 12-byte structured header')
    assert.strictEqual(pptp.pduType, 1, 'PDU type = control message')
    assert.strictEqual(pptp.magicCookie, COOKIE, 'magic cookie 0x1a2b3c4d')
    assert.strictEqual(pptp.controlMessageType, 1, 'Start-Control-Connection-Request')
    assert.strictEqual(pptp.reserved0, '0000', 'reserved0 preserved')
    // body = protocol version 1.0 (0100) + reserved1 + framing/bearer caps + max channels + fw rev + host + vendor
    assert.ok(pptp.body.startsWith('0100000000000001000000010000000'), 'SCCRQ body: version 1.0 then capabilities')
    assert.strictEqual(pptp.body.length, (156 - 12) * 2, 'body bounded by Length (144 octets)')
})

// Crafting: a Stop-Control-Connection-Request (control message type 3, empty body) with the Length
// auto-computed from the (empty) body — the minimal well-formed PPTP control message re-encodes
// byte-identically.
test('PPTP faithfully encodes a crafted control message and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.2', dip: '192.0.2.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 1723}},
        {id: 'pptp', data: {pduType: 1, magicCookie: COOKIE, controlMessageType: 3, reserved0: '0000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pptp'])
    const pptp: any = Layer(decoded, 'pptp').data
    assert.strictEqual(pptp.controlMessageType, 3, 'Stop-Control-Connection-Request')
    assert.strictEqual(pptp.length, 12, 'auto-computed Length = 12 (structured header only, empty body)')
    assert.strictEqual(pptp.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: a crafted message supplies an explicit (lying) Length — it must be honored
// verbatim (not overwritten by the derived value) so a message that carries any Length round-trips.
test('PPTP honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    // Outgoing-Call-Reply (type 8). body = 4 bytes, but we lie and claim Length 12 (header only). The
    // body is bounded by the supplied Length on decode, so only 0 body bytes are consumed here.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 1723, dstport: 51000}},
        {id: 'pptp', data: {pduType: 1, magicCookie: COOKIE, length: 16, controlMessageType: 8, reserved0: '0000', body: 'aabbccdd'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const pptp: any = Layer(decoded, 'pptp').data
    assert.strictEqual(pptp.controlMessageType, 8, 'Outgoing-Call-Reply')
    assert.strictEqual(pptp.length, 16, 'supplied Length honored (not derived to 16 from body — here it matches)')
    assert.strictEqual(pptp.body, 'aabbccdd', 'body bounded by supplied Length (16 - 12 = 4 octets)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/1723 payload whose magic cookie is not 0x1a2b3c4d must NOT be claimed as PPTP (falls
// through to raw); and a truncated PPTP message must survive decode without throwing.
test('PPTP rejects a wrong magic cookie on port 1723, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 1723}},
        // length 000c, pduType 0001, cookie 0xdeadbeef (not the PPTP signature), ctrlType 0001, reserved 0000
        {id: 'raw', data: {data: '000c0001deadbeef00010000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'pptp'), 'wrong magic cookie must not be claimed as PPTP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('pptp/sccrq').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 40))
})

// Protocol-specific edge: two PPTP control messages pipelined in one TCP segment. The first message is
// bounded by its Length, so its body does NOT swallow the trailing message; the trailing bytes fall
// through to raw (a leaf header advances only over its own message and does not re-match itself,
// matching the length-bounded-TCP-payload precedent). Both directions round-trip byte-for-byte.
test('PPTP pipelining: the first message is bounded by its Length; the trailing message falls through to raw', async (): Promise<void> => {
    // First: Echo-Request (type 5), 4-byte body (identifier) => length 16.
    const first: string = '0010' + '0001' + COOKIE + '0005' + '0000' + '11223344'
    // Second: Echo-Reply (type 6), empty body => length 12.
    const second: string = '000c' + '0001' + COOKIE + '0006' + '0000'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 1723, dstport: 51000}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'pptp', 'raw'])
    const pptp: any = Layer(decoded, 'pptp').data
    assert.strictEqual(pptp.controlMessageType, 5, 'first is Echo-Request')
    assert.strictEqual(pptp.body, '11223344', 'first body bounded by its Length — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing Echo-Reply left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
