import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// OMRON FINS (udp:9600) Memory Area Read request — 10-byte FINS header + 2-byte command + body.
test('FINS Memory Area Read: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('fins/memory-area-read').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'fins'])
    const fins: any = Layer(decoded, 'fins').data
    assert.strictEqual(fins.icf, 0x80, 'ICF: command, response required')
    assert.strictEqual(fins.rsv, 0x00, 'reserved')
    assert.strictEqual(fins.gct, 0x02, 'gateway count')
    assert.strictEqual(fins.dna, 0, 'dest network')
    assert.strictEqual(fins.da1, 10, 'dest node')
    assert.strictEqual(fins.da2, 0, 'dest unit')
    assert.strictEqual(fins.sna, 0, 'src network')
    assert.strictEqual(fins.sa1, 1, 'src node')
    assert.strictEqual(fins.sa2, 0, 'src unit')
    assert.strictEqual(fins.sid, 0, 'service id')
    assert.strictEqual(fins.command, 0x0101, 'Memory Area Read')
    assert.strictEqual(fins.body, '820064000001', 'read DM area word 100, 1 item')
})

// Crafting: a minimal Controller Status Read (command 0x0501, empty body) — the smallest well-formed
// UDP FINS message (12 bytes: 10-byte header + command) must re-encode byte-identically.
test('FINS faithfully encodes a crafted Controller Status Read with an empty body', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.250.1', dip: '192.168.250.10', protocol: 17}},
        {id: 'udp', data: {srcport: 9600, dstport: 9600}},
        {id: 'fins', data: {icf: 0x80, gct: 0x02, da1: 10, sa1: 1, command: 0x0501}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'fins'])
    const fins: any = Layer(decoded, 'fins').data
    assert.strictEqual(fins.command, 0x0501, 'Controller Status Read')
    assert.strictEqual(fins.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Crafting: a Memory Area Write (command 0x0102) carrying a parameter/data body — the body is kept
// verbatim and re-encoded faithfully (a crafted message may carry any command/body).
test('FINS faithfully encodes a crafted Memory Area Write with a body', async (): Promise<void> => {
    // body: area 0xB0 (DM word), addr 0x0064, bit 0x00, count 0x0001, data 0x1234
    const writeBody: string = 'b0006400000112 34'.replace(/\s/g, '')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.250.1', dip: '192.168.250.10', protocol: 17}},
        {id: 'udp', data: {srcport: 9600, dstport: 9600}},
        {id: 'fins', data: {icf: 0x80, gct: 0x02, da1: 10, sa1: 1, command: 0x0102, body: writeBody}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const fins: any = Layer(decoded, 'fins').data
    assert.strictEqual(fins.command, 0x0102, 'Memory Area Write')
    assert.strictEqual(fins.body, writeBody, 'body kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/9600 datagram shorter than the 12-byte FINS header+command must NOT be claimed as
// FINS (falls through to raw); and a truncated FINS message must survive decode without throwing.
test('FINS rejects a too-short datagram on port 9600, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.250.1', dip: '192.168.250.10', protocol: 17}},
        {id: 'udp', data: {srcport: 9600, dstport: 9600}},
        // 10 bytes only — a full FINS header but no command code (< 12 bytes)
        {id: 'raw', data: {data: '800002000a0000010000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'fins'), 'too-short datagram must not be claimed as FINS')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('fins/memory-area-read').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 3))
})
