import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'
import {CodecEncodeInput} from '../../../src/types/CodecEncodeInput'

const ETH: CodecEncodeInput = {id: 'eth', data: {dmac: '02:00:00:00:00:01', smac: '02:00:00:00:00:02', etherType: '0800'}}
const IPV4: CodecEncodeInput = {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}}
const UDP: CodecEncodeInput = {id: 'udp', data: {srcport: 40000, dstport: 12201}}

// GELF (udp:12201) chunked datagram — 12-byte chunk header (magic 0x1e0f + msgId + seq + count) + slice.
test('GELF chunked: chunk header + data + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('gelf/chunked').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'gelf'])
    const gelf: any = Layer(decoded, 'gelf').data
    assert.strictEqual(gelf.form, 'chunked', 'leading magic 0x1e0f => chunked')
    assert.strictEqual(gelf.magic, '1e0f', 'GELF chunk magic')
    assert.strictEqual(gelf.messageId, '0123456789abcdef', '8-byte message id')
    assert.strictEqual(gelf.sequenceNumber, 0, 'chunk index 0')
    assert.strictEqual(gelf.sequenceCount, 2, 'total 2 chunks')
    assert.strictEqual(gelf.data, '1f8b080000000000', 'chunk slice kept verbatim')
})

// gzip form (magic 0x1f8b): the whole datagram is an opaque gzip-compressed document, kept verbatim.
test('GELF gzip form: opaque payload round-trips byte-for-byte', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        ETH, IPV4, UDP,
        {id: 'gelf', data: {payload: '1f8b08000000000000ff0102030405'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'gelf'])
    const gelf: any = Layer(decoded, 'gelf').data
    assert.strictEqual(gelf.form, 'gzip', 'leading magic 0x1f8b => gzip')
    assert.strictEqual(gelf.payload, '1f8b08000000000000ff0102030405', 'gzip body verbatim (magic included)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Uncompressed form: no magic — the datagram is the GELF JSON document as UTF-8 text, kept verbatim.
test('GELF uncompressed form: JSON text kept verbatim and round-trips', async (): Promise<void> => {
    const json: string = Buffer.from('{"version":"1.1","host":"h","short_message":"hi"}', 'utf8').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        ETH, IPV4, UDP,
        {id: 'gelf', data: {message: json}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'gelf'])
    const gelf: any = Layer(decoded, 'gelf').data
    assert.strictEqual(gelf.form, 'uncompressed', 'no chunk/gzip magic => uncompressed')
    assert.strictEqual(gelf.message, json, 'JSON body verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// The form is inferred on encode when not supplied: a crafted chunk (message id present) writes the
// 0x1e0f magic and re-decodes as chunked, byte-identically.
test('GELF infers the chunked form from a supplied message id and auto-writes the magic', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        ETH, IPV4, UDP,
        {id: 'gelf', data: {messageId: 'aabbccddeeff0011', sequenceNumber: 1, sequenceCount: 4, data: 'cafe'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const gelf: any = Layer(decoded, 'gelf').data
    assert.strictEqual(gelf.form, 'chunked', 'inferred chunked')
    assert.strictEqual(gelf.magic, '1e0f', 'magic auto-written')
    assert.strictEqual(gelf.sequenceNumber, 1, 'chunk 1')
    assert.strictEqual(gelf.sequenceCount, 4, 'of 4')
    assert.strictEqual(gelf.data, 'cafe', 'chunk slice')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative / edge: an empty UDP/12201 datagram is NOT claimed as GELF (falls through — nothing rides on
// it); and a truncated chunk header survives decode without throwing.
test('GELF does not claim an empty datagram; a truncated chunk survives decode', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([ETH, IPV4, UDP])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'gelf'), 'empty payload must not be claimed as GELF')

    const full: Buffer = LoadPacket('gelf/chunked').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 15))
})
