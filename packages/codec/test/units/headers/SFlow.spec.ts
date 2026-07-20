import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, LayerIds, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'

// Synthesized sFlow v5 datagram (1 counter sample) over UDP 51234 -> 6343, assembled through the encoder
// so the eth/ip/udp envelope is valid. sFlow v5 header + numSamples * (8-byte tag + opaque body).
test('sFlow v5 datagram: field decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('sflow/datagram').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'sflow'])
    const sf: any = Layer(decoded, 'sflow').data
    assert.strictEqual(sf.version, 5, 'version 5')
    assert.strictEqual(sf.agentAddressType, 1, 'IPv4 agent address type')
    assert.strictEqual(sf.agentAddress, '192.168.1.1', 'IPv4 agent address decoded dotted-quad')
    assert.strictEqual(sf.sequenceNumber, 12345)
    assert.strictEqual(sf.sysUptime, 987654321)
    assert.strictEqual(sf.numSamples, 1, 'one sample')
    assert.strictEqual(sf.samples.length, 1, 'one sample record decoded')
    assert.strictEqual(sf.samples[0].sampleType, 2, 'counter-sample format tag')
    assert.strictEqual(sf.samples[0].sampleLength, 48, 'opaque body length')
})

// A crafted 2-sample datagram must re-encode byte-identically (tag+length+opaque-body symmetry).
test('sFlow v5 crafted 2-sample datagram re-encodes byte-identically', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.1.1.1', dip: '10.2.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 6343}},
        {id: 'sflow', data: {
            version: 5, agentAddressType: 1, agentAddress: '203.0.113.7',
            subAgentId: 3, sequenceNumber: 42, sysUptime: 100000, numSamples: 2,
            samples: [
                {sampleType: 1, sampleLength: 12, sampleData: 'aabbccdd112233440000ffff'},
                {sampleType: (5 << 12) | 2, sampleLength: 4, sampleData: 'deadbeef'}
            ]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'sflow'])
    const sf: any = Layer(decoded, 'sflow').data
    assert.strictEqual(sf.numSamples, 2)
    assert.strictEqual(sf.samples.length, 2)
    assert.strictEqual(sf.samples[1].sampleType, (5 << 12) | 2, 'enterprise<<12|format tag round-trips exactly')
    const re: {packet: Buffer} = await codec.encode(decoded)
    assert.strictEqual(re.packet.toString('hex'), packet.toString('hex'), '2-sample datagram round-trip byte-identical')
})

// numSamples is honored when supplied and derived from samples.length when absent; a lying numSamples
// larger than the captured samples must clamp the walk (no over-read) and still round-trip byte-for-byte.
test('sFlow v5 numSamples honor-else-derive; lying numSamples clamps the sample walk', async (): Promise<void> => {
    const samples: any[] = [
        {sampleType: 1, sampleLength: 8, sampleData: '0011223344556677'},
        {sampleType: 2, sampleLength: 4, sampleData: '89abcdef'}
    ]
    // Honor: craft with a lying numSamples of 9 but only 2 samples of actual bytes.
    const {packet: lying}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 6343, dstport: 6343}},
        {id: 'sflow', data: {version: 5, agentAddressType: 1, agentAddress: '10.0.0.9', numSamples: 9, samples: samples}}
    ])
    const decodedLying: CodecDecodeResult[] = await codec.decode(lying)
    assert.ok(!LayerIds(decodedLying).includes('raw'), 'no trailing raw layer; header fully consumed')
    const sfLying: any = Layer(decodedLying, 'sflow').data
    assert.strictEqual(sfLying.numSamples, 9, 'lying numSamples is honored (preserved) on decode')
    assert.strictEqual(sfLying.samples.length, 2, 'sample walk clamps to the 2 captured samples — no over-read')
    const reLying: {packet: Buffer} = await codec.encode(decodedLying)
    assert.strictEqual(reLying.packet.toString('hex'), lying.toString('hex'), 'lying-numSamples datagram round-trips byte-for-byte')

    // Derive: omit numSamples entirely -> it is filled from samples.length.
    const {packet: derived}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 6343, dstport: 6343}},
        {id: 'sflow', data: {version: 5, agentAddressType: 1, agentAddress: '10.0.0.9', samples: samples}}
    ])
    const sfDerived: any = Layer(await codec.decode(derived), 'sflow').data
    assert.strictEqual(sfDerived.numSamples, 2, 'numSamples derived from samples.length when absent')
    assert.strictEqual(sfDerived.samples.length, 2)
})

// A non-v5 payload on port 6343 must NOT be claimed by sFlow (version signature guard); it falls to raw.
// And a truncated sFlow frame must decode without throwing.
test('sFlow v5 rejects non-v5 version and survives truncation', async (): Promise<void> => {
    // 28 bytes of "sFlow"-shaped payload but version = 4.
    const payload: string = '00000004' + '00'.repeat(24)
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 6343, dstport: 6343}},
        {id: 'raw', data: {data: payload}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!LayerIds(decoded).includes('sflow'), 'version 4 is not decoded as sFlow v5')
    assert.ok(LayerIds(decoded).includes('raw'), 'non-v5 payload falls to raw')

    // Truncation mid-sample: decode survives.
    const full: Buffer = LoadPacket('sflow/datagram').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 20))
})

// An IPv6-agent datagram (agentAddressType 2, 16-byte address) shifts every downstream offset by 12
// bytes relative to IPv4. Decoding the trailing fields and samples correctly, then round-tripping,
// proves the conditional agent-address length drives the offsets.
test('sFlow v5 IPv6-agent datagram shifts downstream offsets and round-trips', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '66:77:88:99:aa:bb', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 6343, dstport: 6343}},
        {id: 'sflow', data: {
            version: 5, agentAddressType: 2, agentAddress: '20010db8000000000000000000000001',
            subAgentId: 7, sequenceNumber: 99, sysUptime: 555, numSamples: 2,
            samples: [
                {sampleType: 1, sampleLength: 8, sampleData: 'aabbccdd11223344'},
                {sampleType: 2, sampleLength: 4, sampleData: 'deadbeef'}
            ]
        }}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'sflow'])
    const sf: any = Layer(decoded, 'sflow').data
    assert.strictEqual(sf.agentAddressType, 2, 'IPv6 agent address type')
    assert.strictEqual(sf.agentAddress, '20010db8000000000000000000000001', '16-byte IPv6 agent address kept verbatim as hex')
    // The four post-address fields must decode from their shifted offsets (8 + 16 = 24), not 8 + 4 = 12.
    assert.strictEqual(sf.subAgentId, 7, 'subAgentId read from IPv6-shifted offset')
    assert.strictEqual(sf.sequenceNumber, 99)
    assert.strictEqual(sf.sysUptime, 555)
    assert.strictEqual(sf.numSamples, 2)
    assert.strictEqual(sf.samples.length, 2, 'samples walked from the IPv6-shifted header length')
    assert.strictEqual(sf.samples[0].sampleData, 'aabbccdd11223344')
    assert.strictEqual(sf.samples[1].sampleData, 'deadbeef')
})
