import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// SCTP (ipproto:132) INIT packet — 12-byte common header + one INIT chunk; byte-perfect round-trip.
test('SCTP INIT: common header + INIT chunk + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('sctp/init').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'sctp'])
    const sctp: any = Layer(decoded, 'sctp').data
    assert.strictEqual(sctp.srcPort, 1234, 'source port')
    assert.strictEqual(sctp.dstPort, 5678, 'destination port')
    assert.strictEqual(sctp.verificationTag, '00000000', 'INIT verification tag is 0')
    assert.strictEqual(sctp.checksum, '886a6952', 'CRC32c honored verbatim (little-endian on wire)')
    assert.strictEqual(sctp.chunks.length, 1, 'one chunk')
    assert.strictEqual(sctp.chunks[0].type, 1, 'INIT')
    assert.strictEqual(sctp.chunks[0].flags, 0, 'no flags')
    assert.strictEqual(sctp.chunks[0].length, 20, 'chunk length incl 4-byte chunk header')
    assert.strictEqual(sctp.chunks[0].value, '123456780001ffff00050005000003e8', 'INIT body')
    assert.strictEqual(sctp.chunks[0].padding, '', 'INIT chunk is 4-byte aligned — no padding')
})

// Crafting: a COOKIE_ACK (type 11, empty value) with the Chunk Length auto-computed from the (empty)
// value. The checksum is honored verbatim (default all-zero when crafted, not recomputed).
test('SCTP faithfully encodes a crafted COOKIE_ACK and auto-computes the Chunk Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 132}},
        {id: 'sctp', data: {srcPort: 9, dstPort: 9, verificationTag: 'deadbeef', chunks: [{type: 11, flags: 0}]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'sctp'])
    const sctp: any = Layer(decoded, 'sctp').data
    assert.strictEqual(sctp.verificationTag, 'deadbeef', 'verification tag')
    assert.strictEqual(sctp.checksum, '00000000', 'checksum honored verbatim (not recomputed)')
    assert.strictEqual(sctp.chunks[0].type, 11, 'COOKIE_ACK')
    assert.strictEqual(sctp.chunks[0].length, 4, 'auto-computed Chunk Length = 4 (header only, empty value)')
    assert.strictEqual(sctp.chunks[0].value, '', 'empty value')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Padding round-trip + honor-else-derive: a COOKIE_ECHO (type 10) whose 5-byte value needs 3 pad bytes
// to reach a 4-byte boundary. The Chunk Length (9) excludes the pad; the verbatim pad must reproduce.
test('SCTP honors an explicit Chunk Length and round-trips the alignment padding', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 132}},
        {id: 'sctp', data: {srcPort: 100, dstPort: 200, verificationTag: '00000001', checksum: '11223344',
            chunks: [{type: 10, flags: 0, length: 9, value: 'a1b2c3d4e5', padding: '000000'}]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const sctp: any = Layer(decoded, 'sctp').data
    assert.strictEqual(sctp.checksum, '11223344', 'supplied checksum honored')
    assert.strictEqual(sctp.chunks[0].type, 10, 'COOKIE_ECHO')
    assert.strictEqual(sctp.chunks[0].length, 9, 'supplied Chunk Length honored')
    assert.strictEqual(sctp.chunks[0].value, 'a1b2c3d4e5', '5-byte cookie value')
    assert.strictEqual(sctp.chunks[0].padding, '000000', '3 pad bytes to the 4-byte boundary')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Multi-chunk bundling: an SCTP packet may carry several chunks. A HEARTBEAT (4) followed by a SACK (3)
// must both decode, and the packet round-trips byte-for-byte.
test('SCTP bundles multiple chunks in one packet', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 132}},
        {id: 'sctp', data: {srcPort: 3000, dstPort: 3001, verificationTag: 'aabbccdd', chunks: [
            {type: 4, flags: 0, length: 8, value: '00010004'},
            {type: 3, flags: 0, length: 16, value: '0000000a0000ffff00000000'}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'sctp'])
    const sctp: any = Layer(decoded, 'sctp').data
    assert.strictEqual(sctp.chunks.length, 2, 'two bundled chunks')
    assert.strictEqual(sctp.chunks[0].type, 4, 'HEARTBEAT')
    assert.strictEqual(sctp.chunks[1].type, 3, 'SACK')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative / robustness: a truncated SCTP packet (cut mid-chunk) must survive decode without throwing,
// and a chunk whose Length overruns the IP payload stops the walk (remainder falls through to raw).
test('SCTP survives truncation and stops on an overrunning chunk Length', async (): Promise<void> => {
    const full: Buffer = LoadPacket('sctp/init').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))

    // A common header + a lone chunk header claiming length 40 while only ~4 value bytes are present.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 132}},
        {id: 'raw', data: {data: '04d2162e00000000000000000100002812345678'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const sctp: any = Layer(decoded, 'sctp').data
    assert.strictEqual(sctp.chunks.length, 0, 'overrunning chunk Length stops the walk — no chunk claimed')
    assert.ok(decoded.some((l: CodecDecodeResult): boolean => l.id === 'raw'), 'unparsed remainder falls through to raw')
})

// Regression (was a byte-perfect break): a chunk with an empty value (COOKIE_ACK / SHUTDOWN_ACK, Length 4),
// especially as the trailing chunk, must be fully consumed — not leaked to a trailing RawData layer and
// duplicated on re-encode. The chunk-header reads are dryRun peeks, so an empty trailing chunk otherwise
// fell outside the header's consumed range.
test('SCTP consumes an empty trailing chunk (COOKIE_ACK) without double-counting it', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 132}},
        {id: 'sctp', data: {srcPort: 1234, dstPort: 5678, verificationTag: 0xabcd, checksum: 0, chunks: [
            {type: 3, flags: 0, value: '00000000', padding: ''},
            {type: 11, flags: 0, value: '', padding: ''}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'sctp'])   // no phantom trailing raw from the empty COOKIE_ACK
    const sctp: any = Layer(decoded, 'sctp').data
    assert.strictEqual(sctp.chunks.length, 2, 'both chunks captured, including the empty trailing COOKIE_ACK')
    assert.strictEqual(sctp.chunks[1].value, '', 'the COOKIE_ACK carries an empty value')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect, not duplicated')
})
