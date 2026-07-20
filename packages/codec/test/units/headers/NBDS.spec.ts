import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// The body of the fixture: second-level encoded Source (COMPUTER1<00>) + Destination (WORKGROUP<00>)
// NetBIOS names followed by the SMB mailslot user data ("\MAILSLOT\BROWSE\0").
const BODY: string = '2045444550454e46414646464545464643444243414341434143414341434141410020464845504643454c454846434550464646414341434143414341434143414141005c4d41494c534c4f545c42524f57534500'

// NBDS (udp:138) Direct Group Datagram (RFC 1002 §4.4) — 10-byte common prefix + Datagram Length /
// Packet Offset words + names + user data; byte-perfect round-trip.
test('NBDS Direct Group: prefix + length/offset + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('nbds/direct-group').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'nbds'])
    const nbds: any = Layer(decoded, 'nbds').data
    assert.strictEqual(nbds.msgType, 0x11, 'Direct Group Datagram')
    assert.strictEqual(nbds.flags, 0x02, 'FIRST_FLAG set, B-node, no MORE')
    assert.strictEqual(nbds.dgmId, 0x8025, 'Datagram ID')
    assert.strictEqual(nbds.sourceIP, '192.168.1.10', 'Source IP')
    assert.strictEqual(nbds.sourcePort, 138, 'Source Port')
    assert.strictEqual(nbds.dgmLength, 85, 'Datagram Length = names(34+34) + user data(17)')
    assert.strictEqual(nbds.packetOffset, 0, 'unfragmented')
    assert.strictEqual(nbds.body, BODY, 'names + user data kept verbatim')
})

// Crafting: a Direct datagram with no Datagram Length supplied — it must be auto-derived from the body
// byte length (honor-else-derive), and the crafted datagram must re-encode byte-identically.
test('NBDS auto-derives the Datagram Length from the body when not supplied', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '192.168.1.2', protocol: 17}},
        {id: 'udp', data: {srcport: 138, dstport: 138}},
        {id: 'nbds', data: {msgType: 0x11, flags: 2, dgmId: 2, sourceIP: '192.168.1.1', sourcePort: 138, body: 'aabbccdd'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'nbds'])
    const nbds: any = Layer(decoded, 'nbds').data
    assert.strictEqual(nbds.dgmLength, 4, 'auto-computed from the 4-byte body')
    assert.strictEqual(nbds.body, 'aabbccdd', 'body verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted datagram supplies an explicit Datagram Length — it must be honored
// verbatim (not overwritten by the derived value) so a datagram carrying any Length round-trips.
test('NBDS honors an explicitly supplied Datagram Length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '192.168.1.2', protocol: 17}},
        {id: 'udp', data: {srcport: 138, dstport: 138}},
        {id: 'nbds', data: {msgType: 0x12, flags: 2, dgmId: 3, sourceIP: '192.168.1.1', sourcePort: 138, dgmLength: 999, packetOffset: 0, body: 'aabb'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const nbds: any = Layer(decoded, 'nbds').data
    assert.strictEqual(nbds.msgType, 0x12, 'BROADCAST datagram')
    assert.strictEqual(nbds.dgmLength, 999, 'supplied Length honored, not derived to 2')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Type-dependent layout: a DATAGRAM ERROR (0x13) has NO Datagram Length / Packet Offset words — the
// type-specific tail (the error code byte) follows the 10-byte common prefix directly and round-trips.
test('NBDS DATAGRAM ERROR (0x13) carries no length/offset words', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '192.168.1.2', protocol: 17}},
        {id: 'udp', data: {srcport: 138, dstport: 138}},
        {id: 'nbds', data: {msgType: 0x13, flags: 0, dgmId: 1, sourceIP: '192.168.1.1', sourcePort: 138, body: '82'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const nbds: any = Layer(decoded, 'nbds').data
    assert.strictEqual(nbds.msgType, 0x13, 'DATAGRAM ERROR')
    assert.strictEqual(nbds.body, '82', 'error code byte kept as body directly after the 10-byte prefix')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a sub-10-byte UDP/138 payload is too short for the common prefix — it must NOT be claimed as
// NBDS (falls through to raw); and a truncated datagram must survive decode without throwing.
test('NBDS rejects a too-short payload on port 138, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '192.168.1.2', protocol: 17}},
        {id: 'udp', data: {srcport: 138, dstport: 138}},
        // 6-byte payload (< the 10-byte common prefix), unsigned bytes with no registered content heuristic
        {id: 'raw', data: {data: 'deadbeef0011'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'nbds'), 'too-short payload must not be claimed as NBDS')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('nbds/direct-group').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 90))
})

// Regression (was a byte-perfect break): a Direct/Broadcast datagram (0x10-0x12) shorter than the 14-byte
// fixed header must NOT be claimed as NBDS — its Datagram Length + Packet Offset words are always
// re-emitted on encode, so a 10-13 byte direct datagram would otherwise sprout bytes the wire never had.
// It falls through to raw and round-trips byte-for-byte instead.
test('NBDS: a short Direct datagram (<14 bytes) is left to raw, not claimed', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '192.168.1.2', protocol: 17}},
        {id: 'udp', data: {srcport: 138, dstport: 138}},
        // msgType 0x11 (DIRECT_GROUP) but only 12 bytes — 2 short of the 14-byte Direct fixed header
        {id: 'raw', data: {data: '11021234c0a801010089abcd'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'nbds'), 'short Direct datagram must not be claimed as NBDS')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
