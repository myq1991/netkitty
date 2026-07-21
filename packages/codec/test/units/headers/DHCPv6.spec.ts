import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'

// Real DHCPv6 SOLICIT (client → server) over IPv6, from dhclient -6 against dnsmasq. RFC 8415.
test('DHCPv6 solicit: message + options decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('dhcpv6/solicit').buffer)
    AssertLayers(decoded, ['eth', 'ipv6', 'udp', 'dhcpv6'])
    const dhcpv6: any = Layer(decoded, 'dhcpv6').data
    assert.strictEqual(dhcpv6.msgType, 1, 'SOLICIT')
    assert.strictEqual(dhcpv6.transactionId, '2d6f45')
    // Client Identifier(1), Option Request(6), Elapsed Time(8), IA_NA(3).
    assert.deepStrictEqual(dhcpv6.options.map((o: any): number => o.code), [1, 6, 8, 3])
    assert.strictEqual(dhcpv6.options[0].code, 1, 'Client Identifier')
})

// Real DHCPv6 REPLY (server → client). Richer options incl. IA_NA with a nested address + status.
test('DHCPv6 reply: server options decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('dhcpv6/reply').buffer)
    const dhcpv6: any = Layer(decoded, 'dhcpv6').data
    assert.strictEqual(dhcpv6.msgType, 7, 'REPLY')
    assert.strictEqual(dhcpv6.transactionId, '8f3328')
    assert.deepStrictEqual(dhcpv6.options.map((o: any): number => o.code), [1, 2, 3, 13, 23])
    // IA_NA (option 3) data is kept verbatim (IAID + T1 + T2 + nested IA Address sub-option).
    const iaNa: any = dhcpv6.options.find((o: any): boolean => o.code === 3)
    assert.ok(iaNa.value.startsWith('25bcf3a1'), 'IA_NA data begins with the IAID, kept verbatim')
})

// Negative / crafting: a relay-agent message (RELAY-FORW, type 12) has a different body — it must be
// kept verbatim (rawBody), not misparsed as a transaction-id. Craft one and confirm byte-perfect.
test('DHCPv6 relay message body is kept verbatim (rawBody) and round-trips', async (): Promise<void> => {
    const relayBody: string = '00' + 'fd00000000000000000000000000000a' + 'fe80000000000000000000000000000b' + '000900' // hop-count + link + peer + a stub option
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '86dd'}},
        {id: 'ipv6', data: {sip: 'fe80::1', dip: 'ff02::1:2', nxt: 17}},
        {id: 'udp', data: {srcport: 547, dstport: 547}},
        {id: 'dhcpv6', data: {msgType: 12, rawBody: relayBody}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const dhcpv6: any = Layer(decoded, 'dhcpv6').data
    assert.strictEqual(dhcpv6.msgType, 12, 'RELAY-FORW')
    assert.strictEqual(dhcpv6.rawBody, relayBody, 'relay body preserved verbatim, not parsed as xid+options')
    assert.strictEqual(dhcpv6.transactionId, undefined)
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// A capture that retained the Ethernet FCS (or L2 padding) must still round-trip: the option walk is
// bounded by the UDP payload length, so the trailing bytes spill to the raw layer instead of being
// swallowed as bogus options. (Regression for a critic finding — byte-perfect for retained-FCS captures.)
test('DHCPv6 with trailing bytes after the UDP payload keeps them in raw and round-trips', async (): Promise<void> => {
    const withTrailer: Buffer = Buffer.concat([LoadPacket('dhcpv6/solicit').buffer, Buffer.from('deadbeef', 'hex')])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(withTrailer)
    AssertLayers(decoded, ['eth', 'ipv6', 'udp', 'dhcpv6', 'raw'])
    // The DHCPv6 options do not absorb the trailing bytes.
    assert.deepStrictEqual((Layer(decoded, 'dhcpv6').data as any).options.map((o: any): number => o.code), [1, 6, 8, 3])
})

// A degenerate 1-byte relay message (just the msg-type) must round-trip to exactly that 1 byte, not be
// re-emitted with a fabricated transaction-id. (Regression for a critic finding.)
test('DHCPv6 one-byte relay message round-trips to a single byte', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '86dd'}},
        {id: 'ipv6', data: {sip: 'fe80::1', dip: 'ff02::1:2', nxt: 17}},
        {id: 'udp', data: {srcport: 547, dstport: 547}},
        {id: 'dhcpv6', data: {msgType: 12, rawBody: ''}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const dhcpv6: any = Layer(decoded, 'dhcpv6').data
    assert.strictEqual(dhcpv6.msgType, 12)
    assert.strictEqual(dhcpv6.transactionId, undefined, 'no fabricated transaction-id for a relay')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

test('DHCPv6 truncated mid-option: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('dhcpv6/reply').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 10))
})
