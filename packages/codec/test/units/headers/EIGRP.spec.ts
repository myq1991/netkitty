import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// EIGRP (ip proto 88) Hello — 20-byte fixed header + a Parameters TLV and a Software Version TLV.
test('EIGRP Hello: header + TLV chain + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('eigrp/hello').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'eigrp'])
    const eigrp: any = Layer(decoded, 'eigrp').data
    assert.strictEqual(eigrp.version, 2, 'version 2')
    assert.strictEqual(eigrp.opcode, 5, 'Hello')
    assert.strictEqual(eigrp.checksum, 0xee68, 'checksum honored verbatim')
    assert.strictEqual(eigrp.flags, 0, 'flags')
    assert.strictEqual(eigrp.sequence, 0, 'sequence')
    assert.strictEqual(eigrp.ack, 0, 'acknowledge')
    assert.strictEqual(eigrp.virtualRouterId, 0, 'virtual router id')
    assert.strictEqual(eigrp.autonomousSystem, 100, 'AS 100')
    assert.deepStrictEqual(eigrp.tlvs, [
        {type: 1, length: 12, value: '010001000000000f'}, // Parameters: K1..K6 + hold time 15
        {type: 4, length: 8, value: '0c040102'}            // Software Version: EIGRP 12.4 / TLV 1.2
    ], 'Parameters + Software Version TLVs kept verbatim')
})

// honor-else-derive: an explicit Length is honored verbatim even when it disagrees with the value byte
// count (a crafted TLV may lie), and a Length that overruns the IP payload clamps the value on decode but
// re-emits the lie byte-for-byte.
test('EIGRP honors an explicit TLV Length (does not derive over it), and derives when omitted', async (): Promise<void> => {
    // Supplied length 12 for a self-consistent Parameters TLV; a second TLV with the Length omitted must be
    // derived as 4 (header) + value byte count.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '224.0.0.10', protocol: 88}},
        {id: 'eigrp', data: {version: 2, opcode: 5, autonomousSystem: 100, tlvs: [
            {type: 1, length: 12, value: '010001000000000f'},
            {type: 4, value: '0c040102'}
        ]}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'eigrp'])
    const eigrp: any = Layer(decoded, 'eigrp').data
    assert.strictEqual(eigrp.tlvs[0].length, 12, 'supplied Length honored')
    assert.strictEqual(eigrp.tlvs[1].length, 8, 'omitted Length derived = 4 + 4-byte value')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a non-88 IP payload must NOT be claimed as EIGRP (falls through to raw), and a truncated EIGRP
// packet must survive decode without throwing.
test('EIGRP is not claimed on a non-88 protocol, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '192.168.1.2', protocol: 17}}, // UDP, not EIGRP
        {id: 'raw', data: {data: '0205000000000000000000000000000000000064'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'eigrp'), 'must not be claimed as EIGRP on proto 17')

    const full: Buffer = LoadPacket('eigrp/hello').buffer
    for (let cut: number = 1; cut <= 24; cut++) {
        await AssertDecodeSurvives(full.subarray(0, full.length - cut))
    }
})
