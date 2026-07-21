import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Real RFC 5424 syslog message on UDP 514 from util-linux logger -n. PRI 13 = user.notice.
test('Syslog RFC 5424: PRI split + message decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('syslog/rfc5424').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'syslog'])
    const syslog: any = Layer(decoded, 'syslog').data
    assert.strictEqual(syslog.pri, 13)
    assert.strictEqual(syslog.facility, 1, 'PRI 13 >> 3 = facility 1 (user)')
    assert.strictEqual(syslog.severity, 5, 'PRI 13 & 7 = severity 5 (notice)')
    // The whole message body after <PRI> is kept verbatim (RFC 5424: version + timestamp + ... + msg).
    assert.ok(syslog.message.startsWith('1 2026-'), 'body kept verbatim starting at the version')
    assert.ok(syslog.message.endsWith('hello syslog world'))
})

// Negative / crafting: a message WITHOUT a <PRI> prefix keeps the whole payload as the message and
// round-trips (pri absent); and a crafted <PRI> message is emitted faithfully.
test('Syslog without a PRI prefix keeps the whole payload as the message', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 514}},
        {id: 'syslog', data: {message: 'plain text with no priority <not-a-pri>'}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const syslog: any = Layer(decoded, 'syslog').data
    assert.strictEqual(syslog.pri, undefined, 'no PRI parsed')
    assert.strictEqual(syslog.message, 'plain text with no priority <not-a-pri>')
})

// An out-of-range 3-digit PRI (>191, e.g. "<999>") is NOT a valid syslog priority; it must be kept in
// the message verbatim rather than decoded to a pri that would exceed the schema bounds and make the
// decode result fail re-encode validation. (Regression for a critic finding.)
test('Syslog keeps an out-of-range PRI (>191) in the message and re-encodes without throwing', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 514}},
        {id: 'raw', data: {data: Buffer.from('<999>not a valid priority', 'latin1').toString('hex')}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const syslog: any = Layer(decoded, 'syslog').data
    assert.strictEqual(syslog.pri, undefined, 'out-of-range PRI is not parsed')
    assert.strictEqual(syslog.message, '<999>not a valid priority', 'kept verbatim in the message')
    // The boundary value 191 IS valid (facility 23, severity 7).
    assert.strictEqual(syslog.facility, undefined)
})

// A leading-zero PRI ("<013>") is non-conformant (RFC forbids leading zeros) and would not re-emit
// identically (encode drops the zero) — keep it in the message verbatim so the bytes round-trip.
test('Syslog keeps a leading-zero PRI in the message (byte-perfect, no silent corruption)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 514}},
        {id: 'raw', data: {data: Buffer.from('<013>leading zero pri', 'latin1').toString('hex')}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const syslog: any = Layer(decoded, 'syslog').data
    assert.strictEqual(syslog.pri, undefined, 'leading-zero PRI is not parsed (would not re-emit identically)')
    assert.strictEqual(syslog.message, '<013>leading zero pri')
})

test('Syslog faithfully encodes a crafted <PRI> message and round-trips', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 514}},
        {id: 'syslog', data: {pri: 34, message: 'Oct 11 22:14:15 host su: crafted alert'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const syslog: any = Layer(decoded, 'syslog').data
    assert.strictEqual(syslog.pri, 34)
    assert.strictEqual(syslog.facility, 4, 'PRI 34 >> 3 = facility 4 (auth)')
    assert.strictEqual(syslog.severity, 2, 'PRI 34 & 7 = severity 2 (critical)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})
