import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// DNP3 (IEEE 1815, tcp:20000) read request — the Data Link header + verbatim data-block payload.
test('DNP3 read request: link header + data blocks + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('dnp3/read-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'dnp3'])
    const dnp3: any = Layer(decoded, 'dnp3').data
    assert.strictEqual(dnp3.start, '0564', 'DNP3 start bytes')
    assert.strictEqual(dnp3.length, 11)
    assert.strictEqual(dnp3.control.dir, true, 'direction bit')
    assert.strictEqual(dnp3.control.prm, true, 'primary')
    assert.strictEqual(dnp3.control.functionCode, 4, 'unconfirmed user data')
    assert.strictEqual(dnp3.destination, 4, 'little-endian destination address')
    assert.strictEqual(dnp3.source, 1, 'little-endian source address')
    assert.strictEqual(dnp3.headerCrc, '0130', 'header CRC honored verbatim')
    assert.strictEqual(dnp3.payload, 'c0c0013c0106ff50', 'data block (transport + app + block CRC) kept verbatim')
})

// Crafting: build a link-layer Reset (function 0) with no user data — Length 5, empty payload.
test('DNP3 faithfully encodes a crafted link-layer Reset (no user data)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 20000}},
        {id: 'dnp3', data: {
            start: '0564', length: 5,
            control: {dir: true, prm: true, fcb: false, fcv: false, functionCode: 0},
            destination: 10, source: 20, headerCrc: 'abcd', payload: ''
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'dnp3'])
    const dnp3: any = Layer(decoded, 'dnp3').data
    assert.strictEqual(dnp3.control.functionCode, 0, 'link reset')
    assert.strictEqual(dnp3.destination, 10)
    assert.strictEqual(dnp3.source, 20)
    assert.strictEqual(dnp3.headerCrc, 'abcd', 'CRC honored verbatim (a crafted frame may carry any CRC)')
    assert.strictEqual(dnp3.payload, '')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A TCP/20000 payload without the 0x0564 start signature must fall through to raw.
test('DNP3 rejects a payload without the 0x0564 start signature (falls through to raw)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 20000}},
        {id: 'raw', data: {data: 'deadbeef0bc404000100abcd'}} // no 0564 start
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'dnp3'), 'must not claim a non-DNP3 payload')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
})

test('DNP3 truncated mid-frame: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('dnp3/read-request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})
