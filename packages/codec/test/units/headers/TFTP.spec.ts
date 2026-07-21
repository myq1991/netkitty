import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Encode a TFTP payload (real bytes) onto UDP port 69 to force the port-69 demux, then decode. Used to
// cover DATA/ACK/ERROR, which in real captures move to an ephemeral TID (a T2 conversation).
async function tftpOnPort69(tftpPayloadHex: string): Promise<CodecDecodeResult[]> {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 69}},
        {id: 'raw', data: {data: tftpPayloadHex}}
    ])
    return codec.decode(packet)
}

// Real TFTP Read Request (RRQ) on UDP port 69, from a tftp-hpa GET against tftpd-hpa. RFC 1350.
test('TFTP read request: filename + mode decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tftp/read-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'tftp'])
    const tftp: any = Layer(decoded, 'tftp').data
    assert.strictEqual(tftp.opcode, 1, 'RRQ')
    assert.strictEqual(tftp.filename, 'test.txt')
    assert.strictEqual(tftp.mode, 'octet')
    assert.deepStrictEqual(tftp.options, [], 'no RFC 2347 options')
})

// DATA (opcode 3) — real payload from the same transfer (it rode an ephemeral TID on the wire).
test('TFTP data block: block number + payload decode + byte-perfect round-trip', async (): Promise<void> => {
    const original: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 69}},
        {id: 'raw', data: {data: '0003000168656c6c6f207466747020776f726c640a'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(original.packet)
    const tftp: any = Layer(decoded, 'tftp').data
    assert.strictEqual(tftp.opcode, 3, 'DATA')
    assert.strictEqual(tftp.block, 1)
    assert.strictEqual(tftp.data, '68656c6c6f207466747020776f726c640a', 'payload kept as raw hex')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), original.packet.toString('hex'))
})

// ACK (opcode 4) and ERROR (opcode 5) round-trip too.
test('TFTP ack + error decode and round-trip', async (): Promise<void> => {
    const ack: CodecDecodeResult[] = await tftpOnPort69('00040001')
    assert.strictEqual((Layer(ack, 'tftp').data as any).opcode, 4)
    assert.strictEqual((Layer(ack, 'tftp').data as any).block, 1)

    // ERROR: code 1 (File not found) + "No such file"\0.
    const err: CodecDecodeResult[] = await tftpOnPort69('000500014e6f20737563682066696c6500')
    const errData: any = Layer(err, 'tftp').data
    assert.strictEqual(errData.opcode, 5)
    assert.strictEqual(errData.errorCode, 1)
    assert.strictEqual(errData.errorMessage, 'No such file')
})

// Negative / crafting: a RRQ with RFC 2347 options (blksize, tsize) — the null-terminated name/value
// pairs after the mode — is emitted faithfully and round-trips byte-for-byte.
test('TFTP faithfully encodes a crafted RRQ with RFC 2347 options', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 69}},
        {id: 'tftp', data: {opcode: 2, filename: 'big.iso', mode: 'octet', options: [{name: 'blksize', value: '1428'}, {name: 'tsize', value: '0'}]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const tftp: any = Layer(decoded, 'tftp').data
    assert.strictEqual(tftp.opcode, 2, 'WRQ')
    assert.strictEqual(tftp.filename, 'big.iso')
    assert.deepStrictEqual(tftp.options, [{name: 'blksize', value: '1428'}, {name: 'tsize', value: '0'}])
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

test('TFTP truncated mid-filename: decode survives AND the decode result re-encodes without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('tftp/read-request').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 6))
    // The decode output must always be re-encodable (schema-valid), even for a truncated message.
    await codec.encode(decoded)
})

// A datagram to port 69 too short to hold the 2-byte opcode must NOT be claimed as TFTP (which would
// yield an un-re-encodable empty layer) — it falls through to raw and round-trips. (Critic finding.)
test('TFTP does not claim a sub-2-byte payload on port 69', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 69}},
        {id: 'raw', data: {data: '00'}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'tftp'), 'a 1-byte payload is not TFTP')
})
