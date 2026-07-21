import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'

// SNAP over LLC re-exposes an EtherType, so IPv4 (and ARP/IPv6) route through the shared ethertype demux
// exactly as they do over Ethernet II / 802.1Q — the load-bearing property of the SNAP design.
test('SNAP routes to IPv4 through the shared ethertype demux (OUI 0x000000)', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('snap/ipv4').buffer)
    AssertLayers(decoded, ['eth', 'llc', 'snap', 'ipv4'])
    const snap: any = Layer(decoded, 'snap').data
    assert.strictEqual(snap.oui, '000000', 'OUI 0x000000 (an EtherType PID)')
    assert.strictEqual(snap.etherType, '0800', 'PID re-exposed as EtherType 0x0800')
    const ipv4: any = Layer(decoded, 'ipv4').data
    assert.strictEqual(ipv4.sip, '192.0.2.1', 'IPv4 decoded above SNAP')
})

// CDP: SNAP OUI 0x00000C + PID 0x2000 routes to the Cisco Discovery Protocol via the snapoui demux key.
test('CDP: SNAP (OUI 0x00000C / PID 0x2000) routes to CDP and round-trips byte-perfect', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('cdp/device-id').buffer)
    AssertLayers(decoded, ['eth', 'llc', 'snap', 'cdp'])
    const cdp: any = Layer(decoded, 'cdp').data
    assert.strictEqual(cdp.version, 2, 'CDP version 2')
    assert.strictEqual(cdp.ttl, 180, 'TTL')
    assert.strictEqual(cdp.checksum, 'e2c8', 'checksum honored verbatim')
    assert.strictEqual(cdp.tlvs.length, 1, 'one TLV')
    assert.strictEqual(cdp.tlvs[0].type, 1, 'Device ID TLV')
    assert.strictEqual(cdp.tlvs[0].value, '535731', 'Device ID value "SW1"')
})

// IS-IS: an LLC child by DSAP 0xFE — common header decoded, type-specific part kept verbatim.
test('IS-IS: an LLC (DSAP 0xFE) frame decodes eth/llc/isis and round-trips byte-perfect', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('isis/l1-lan-hello').buffer)
    AssertLayers(decoded, ['eth', 'llc', 'isis'])
    const isis: any = Layer(decoded, 'isis').data
    assert.strictEqual(isis.irpDiscriminator, '83', 'IRP discriminator 0x83')
    assert.strictEqual(isis.pduType, 15, 'L1 LAN Hello')
    assert.strictEqual(isis.body, '010001abcdef00112233', 'type-specific part kept verbatim')
})

// Truncated LLC/SNAP frames survive decode without throwing.
test('SNAP/CDP/IS-IS truncation survives decode', async (): Promise<void> => {
    await AssertDecodeSurvives(LoadPacket('snap/ipv4').buffer.subarray(0, 18))
    await AssertDecodeSurvives(LoadPacket('cdp/device-id').buffer.subarray(0, 20))
    await AssertDecodeSurvives(LoadPacket('isis/l1-lan-hello').buffer.subarray(0, 19))
})
