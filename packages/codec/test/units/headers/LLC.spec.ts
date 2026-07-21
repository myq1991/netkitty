import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// An IEEE 802.3 frame (EtherType field carries a length <= 1500) is an LLC frame; a real STP Config BPDU
// decodes eth -> llc -> stp, with the trailing 802.3 padding falling to raw.
test('LLC + STP: an 802.3 Config BPDU decodes eth/llc/stp and round-trips byte-perfect', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('stp/config-bpdu').buffer)
    AssertLayers(decoded, ['eth', 'llc', 'stp', 'raw'])
    const llc: any = Layer(decoded, 'llc').data
    assert.strictEqual(llc.dsap, 0x42, 'DSAP 0x42 (Spanning Tree)')
    assert.strictEqual(llc.ssap, 0x42, 'SSAP 0x42')
    assert.strictEqual(llc.control, '03', 'U-format UI control (1 byte)')
    const stp: any = Layer(decoded, 'stp').data
    assert.strictEqual(stp.protocolIdentifier, '0000', 'STP protocol identifier')
    assert.strictEqual(stp.protocolVersion, 0, 'version 0 (STP)')
    assert.strictEqual(stp.bpduType, 0, 'Configuration BPDU')
    assert.strictEqual(stp.rootIdentifier, '8000001122334455', 'root identifier')
    assert.strictEqual(stp.rootPathCost, 0, 'root path cost')
    assert.strictEqual(stp.bridgeIdentifier, '8000001122334455', 'bridge identifier')
    assert.strictEqual(stp.portIdentifier, 0x8001, 'port identifier')
    assert.strictEqual(stp.maxAge, 5120, 'max age 20s (0x1400, 1/256s units)')
    assert.strictEqual(stp.helloTime, 512, 'hello time 2s')
    assert.strictEqual(stp.forwardDelay, 3840, 'forward delay 15s')
    // The 8 trailing 802.3 padding bytes are left to raw, not absorbed by STP.
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, '0000000000000000', 'padding falls to raw')
})

// Steal-guard: a normal Ethernet II frame (EtherType 0x0800 >= 0x0600) must still decode as ipv4 — LLC
// must never claim a real EtherType frame.
test('LLC does not steal an Ethernet II frame (EtherType >= 0x0600)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:11:22:33:44:55', smac: '66:77:88:99:aa:bb', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 1111, dstport: 2222}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'llc'), 'a real EtherType frame is not LLC')
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp'])
})

// Boundary: EtherType value exactly 0x05DC (1500) is a length -> LLC claims it; 0x0600 (1536) is a real
// EtherType -> LLC must not claim it (unregistered type falls to raw, never to llc).
test('LLC length/EtherType boundary at 0x05DC vs 0x0600', async (): Promise<void> => {
    // 0x05DC: a length -> llc (DSAP/SSAP 0xAA SNAP-ish header bytes, but with no SNAP child registered here
    // the payload after the 3-byte LLC header just goes to raw — the point is the llc layer appears).
    const atBoundary: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '05dc'}},
        {id: 'raw', data: {data: 'e0e003aabbccdd'}}
    ])
    const belowDecoded: CodecDecodeResult[] = await codec.decode(atBoundary.packet)
    assert.ok(belowDecoded.some((l: CodecDecodeResult): boolean => l.id === 'llc'), '0x05DC is a length -> llc')

    // 0x0600: a real (unregistered) EtherType -> not llc, falls to raw.
    const aboveBoundary: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0600'}},
        {id: 'raw', data: {data: 'e0e003aabbccdd'}}
    ])
    const aboveDecoded: CodecDecodeResult[] = await codec.decode(aboveBoundary.packet)
    assert.ok(!aboveDecoded.some((l: CodecDecodeResult): boolean => l.id === 'llc'), '0x0600 is a real EtherType -> not llc')
    assert.strictEqual(aboveDecoded[aboveDecoded.length - 1].id, 'raw')
})

// A TCN BPDU (type 0x80) is only the 4-byte fixed part — no body fields are read or written, so it
// round-trips as exactly 4 bytes (crafted over LLC).
test('STP TCN BPDU (type 0x80) carries no body and round-trips as 4 bytes', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:00', smac: '00:11:22:33:44:55', etherType: '0005'}},
        {id: 'llc', data: {dsap: 0x42, ssap: 0x42, control: '03'}},
        {id: 'stp', data: {protocolIdentifier: '0000', protocolVersion: 0, bpduType: 0x80}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'llc', 'stp'])
    const stp: any = Layer(decoded, 'stp').data
    assert.strictEqual(stp.bpduType, 0x80, 'TCN BPDU')
    assert.strictEqual(stp.rootIdentifier, undefined, 'no body fields on a TCN BPDU')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')

    // Truncated 802.3/LLC frame survives decode without throwing.
    await AssertDecodeSurvives(LoadPacket('stp/config-bpdu').buffer.subarray(0, 20))
})
