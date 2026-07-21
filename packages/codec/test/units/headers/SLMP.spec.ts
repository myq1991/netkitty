import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// SLMP / MELSEC (udp:5007) 3E-frame BINARY Batch Read request — subheader 0x5000, routing header,
// request data length, then the command payload kept verbatim. Byte-perfect round-trip.
test('SLMP 3E Read request: header + payload + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('slmp/read-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'slmp'])
    const slmp: any = Layer(decoded, 'slmp').data
    assert.strictEqual(slmp.subheader, 0x5000, 'request subheader 0x5000')
    assert.strictEqual(slmp.networkNo, 0, 'network number')
    assert.strictEqual(slmp.stationNo, 0xff, 'station number 0xFF (local)')
    assert.strictEqual(slmp.moduleIO, 0x03ff, 'module I/O 0x03FF (own station, little-endian)')
    assert.strictEqual(slmp.multidropStation, 0, 'multidrop station')
    assert.strictEqual(slmp.requestDataLength, 12, 'request data length (little-endian): payload byte count')
    // payload: monitor timer 0x0010 (LE), command 0x0401 Batch Read (LE), subcommand 0x0000 (LE),
    // device D100 (code 0xA8, head number 100 LE) x 1 point.
    assert.strictEqual(slmp.data, '100001040000640000a80100', 'command payload kept verbatim')
})

// Crafting: a minimal 3E request whose Request Data Length is auto-computed from the (given) payload —
// the encoder must derive the length and reproduce the frame byte-identically on re-encode.
test('SLMP faithfully encodes a crafted request and auto-computes the Request Data Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.10', dip: '192.168.0.20', protocol: 17}},
        {id: 'udp', data: {srcport: 49152, dstport: 5007}},
        // command 0x0101 (self-test) with no device data; payload = timer+command+subcommand = 6 bytes.
        {id: 'slmp', data: {subheader: 0x5000, networkNo: 0, stationNo: 0xff, moduleIO: 0x03ff, multidropStation: 0, data: '100001010000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'slmp'])
    const slmp: any = Layer(decoded, 'slmp').data
    assert.strictEqual(slmp.subheader, 0x5000, 'request subheader')
    assert.strictEqual(slmp.requestDataLength, 6, 'auto-computed Request Data Length = payload byte count')
    assert.strictEqual(slmp.data, '100001010000', 'payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted response (subheader 0xD000) supplies an explicit Request Data Length — it
// must be honored verbatim (not overwritten by the derived value) so a frame carrying any length round-trips.
test('SLMP honors an explicitly supplied Request Data Length and a response subheader', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.20', dip: '192.168.0.10', protocol: 17}},
        {id: 'udp', data: {srcport: 5007, dstport: 49152}},
        // response: end code 0x0000 (LE) + 2 bytes of read data => 4 bytes; supply the length explicitly.
        {id: 'slmp', data: {subheader: 0xd000, networkNo: 0, stationNo: 0xff, moduleIO: 0x03ff, multidropStation: 0, requestDataLength: 4, data: '00006400'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const slmp: any = Layer(decoded, 'slmp').data
    assert.strictEqual(slmp.subheader, 0xd000, 'response subheader 0xD000')
    assert.strictEqual(slmp.requestDataLength, 4, 'supplied Request Data Length honored')
    assert.strictEqual(slmp.data, '00006400', 'end code + read data')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/5007 payload without a valid 3E subheader (not 0x5000 / 0xD000) must NOT be claimed as
// SLMP (falls through to raw); and a truncated SLMP frame must survive decode without throwing.
test('SLMP rejects a non-3E subheader on port 5007, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.10', dip: '192.168.0.20', protocol: 17}},
        {id: 'udp', data: {srcport: 49152, dstport: 5007}},
        // subheader bytes 0x9999 — not the 3E-binary 0x5000 / 0xD000 signature (unsigned, no content magic)
        {id: 'raw', data: {data: '999900ffff03000c001000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'slmp'), 'non-3E subheader must not be claimed as SLMP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('slmp/read-request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})
