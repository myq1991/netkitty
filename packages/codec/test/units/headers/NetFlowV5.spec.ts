import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, LayerIds, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'

// Synthesized NetFlow v5 export (2 records) over UDP 9995 -> 2055, assembled through the encoder so the
// eth/ip/udp envelope is valid. Cisco NetFlow v5 fixed format: 24-byte header + count * 48-byte records.
test('NetFlow v5 export: field decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('netflow/v5').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'netflow5'])
    const nf: any = Layer(decoded, 'netflow5').data
    assert.strictEqual(nf.version, 5, 'version 5')
    assert.strictEqual(nf.count, 2, 'count = 2 records')
    assert.strictEqual(nf.sysUptime, 100600)
    assert.strictEqual(nf.flowSequence, 1024)
    assert.strictEqual(nf.records.length, 2, 'two flow records decoded')
    assert.strictEqual(nf.records[0].srcAddr, '192.168.10.5')
    assert.strictEqual(nf.records[0].dstAddr, '8.8.8.8')
    assert.strictEqual(nf.records[0].dstPort, 443)
    assert.strictEqual(nf.records[0].prot, 6, 'TCP')
    assert.strictEqual(nf.records[0].srcAs, 64500)
    // Second record must be present and independently decoded.
    assert.ok(nf.records[1], 'records[1] present')
    assert.strictEqual(nf.records[1].srcAddr, '10.0.0.23')
    assert.strictEqual(nf.records[1].dstPort, 53)
    assert.strictEqual(nf.records[1].prot, 17, 'UDP')
})

// A crafted single-record packet must re-encode byte-identically (fixed-format symmetry).
test('NetFlow v5 crafted single-record packet re-encodes byte-identically', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.1.1.1', dip: '10.2.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 2055}},
        {id: 'netflow5', data: {
            version: 5, count: 1, sysUptime: 5000, unixSecs: 1700000000, unixNsecs: 12345,
            flowSequence: 7, engineType: 1, engineId: 2, samplingInterval: 100,
            records: [{
                srcAddr: '203.0.113.1', dstAddr: '198.51.100.2', nextHop: '203.0.113.254',
                input: 10, output: 20, dPkts: 42, dOctets: 60000,
                first: 4000, last: 4900, srcPort: 12345, dstPort: 80,
                pad1: 0, tcpFlags: 0x18, prot: 6, tos: 8,
                srcAs: 100, dstAs: 200, srcMask: 24, dstMask: 28, pad2: 0
            }]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'netflow5'])
    const nf: any = Layer(decoded, 'netflow5').data
    assert.strictEqual(nf.count, 1)
    assert.strictEqual(nf.records.length, 1)
    const re: {packet: Buffer} = await codec.encode(decoded)
    assert.strictEqual(re.packet.toString('hex'), packet.toString('hex'), 'single-record round-trip byte-identical')
})

// count is honored when supplied and derived from records.length when absent; a lying count larger than
// the captured records must clamp the record walk (no over-read) and still round-trip byte-for-byte.
test('NetFlow v5 count honor-else-derive; lying count clamps the record walk', async (): Promise<void> => {
    const record: any = {
        srcAddr: '1.1.1.1', dstAddr: '2.2.2.2', nextHop: '3.3.3.3',
        input: 1, output: 1, dPkts: 1, dOctets: 100,
        first: 1, last: 2, srcPort: 1000, dstPort: 2000,
        pad1: 0, tcpFlags: 0, prot: 6, tos: 0,
        srcAs: 1, dstAs: 2, srcMask: 8, dstMask: 8, pad2: 0
    }
    // Honor: craft with a lying count of 5 but only 2 records of actual bytes.
    const {packet: lying}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 9996, dstport: 2055}},
        {id: 'netflow5', data: {version: 5, count: 5, records: [record, {...record, srcAddr: '4.4.4.4'}]}}
    ])
    // The netflow payload must be exactly 24 + 2*48 = 120 bytes (count lied, but only 2 records written).
    const decodedLying: CodecDecodeResult[] = await codec.decode(lying)
    assert.ok(!LayerIds(decodedLying).includes('raw'), 'no trailing raw layer; header fully consumed')
    const nfLying: any = Layer(decodedLying, 'netflow5').data
    assert.strictEqual(nfLying.count, 5, 'lying count is honored (preserved) on decode')
    assert.strictEqual(nfLying.records.length, 2, 'record walk clamps to the 2 captured records — no over-read')
    const reLying: {packet: Buffer} = await codec.encode(decodedLying)
    assert.strictEqual(reLying.packet.toString('hex'), lying.toString('hex'), 'lying-count packet round-trips byte-for-byte')

    // Derive: omit count entirely -> it is filled from records.length.
    const {packet: derived}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 9996, dstport: 2055}},
        {id: 'netflow5', data: {version: 5, records: [record, {...record, srcAddr: '4.4.4.4'}, {...record, srcAddr: '5.5.5.5'}]}}
    ])
    const nfDerived: any = Layer(await codec.decode(derived), 'netflow5').data
    assert.strictEqual(nfDerived.count, 3, 'count derived from records.length when absent')
    assert.strictEqual(nfDerived.records.length, 3)
})

// A non-v5 payload on port 2055 must NOT be claimed by NetFlow v5 (version signature guard); it falls
// to raw. And a truncated NetFlow frame must decode without throwing.
test('NetFlow v5 rejects non-v5 version and survives truncation', async (): Promise<void> => {
    // 24 bytes of "NetFlow"-shaped payload but version = 9.
    const payload: string = '0009' + '00'.repeat(22)
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 9995, dstport: 2055}},
        {id: 'raw', data: {data: payload}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!LayerIds(decoded).includes('netflow5'), 'version 9 is not decoded as NetFlow v5')
    assert.ok(LayerIds(decoded).includes('raw'), 'non-v5 payload falls to raw')

    // Truncation mid-second-record: decode survives.
    const full: Buffer = LoadPacket('netflow/v5').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 30))
})

// A per-record field (IPv4 addresses and ports) must round-trip exactly through decode->encode.
test('NetFlow v5 per-record fields round-trip exactly', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('netflow/v5').buffer)
    const nf: any = Layer(decoded, 'netflow5').data
    assert.strictEqual(nf.records[1].dstAddr, '172.217.16.14', 'record[1] dstAddr decoded exactly')
    assert.strictEqual(nf.records[1].nextHop, '10.0.0.1')
    assert.strictEqual(nf.records[0].srcPort, 51514)
    assert.strictEqual(nf.records[1].srcPort, 33012)
    const re: {packet: Buffer} = await codec.encode(decoded)
    assert.strictEqual(re.packet.toString('hex'), LoadPacket('netflow/v5').buffer.toString('hex'), 'record fields re-encode byte-perfect')
})

// Defense-in-depth: a count=0 export (header only, no records) round-trips, and the 32-bit counters keep
// full unsigned range (a value with the high bit set must NOT decode negative — the fieldUInt/BE contract).
test('NetFlow v5 count=0 header-only and 32-bit high-bit counters round-trip unsigned', async (): Promise<void> => {
    const empty: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '66:77:88:99:aa:bb', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 9995, dstport: 2055}},
        {id: 'netflow5', data: {version: 5, count: 0, records: []}}
    ])
    const emptyDecoded: CodecDecodeResult[] = await AssertRoundTrip(empty.packet)
    AssertLayers(emptyDecoded, ['eth', 'ipv4', 'udp', 'netflow5'])
    assert.strictEqual((Layer(emptyDecoded, 'netflow5').data as any).records.length, 0, 'count=0 → empty records array')

    const bigCounters: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '66:77:88:99:aa:bb', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 9995, dstport: 2055}},
        {id: 'netflow5', data: {version: 5, count: 1, records: [
            {srcAddr: '1.2.3.4', dstAddr: '5.6.7.8', nextHop: '9.10.11.12', dPkts: 0xFFFFFFFF, dOctets: 0x80000001, first: 0x90000000, last: 1, srcPort: 1, dstPort: 2, prot: 6}
        ]}}
    ])
    const bigDecoded: CodecDecodeResult[] = await AssertRoundTrip(bigCounters.packet)
    const r: any = (Layer(bigDecoded, 'netflow5').data as any).records[0]
    assert.strictEqual(r.dPkts, 4294967295, 'dPkts 0xFFFFFFFF decodes unsigned')
    assert.strictEqual(r.dOctets, 2147483649, 'dOctets 0x80000001 (high bit set) decodes unsigned, not negative')
    assert.strictEqual(r.first, 2415919104, 'first 0x90000000 decodes unsigned')
})
