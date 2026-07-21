import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// DHCP Failover (tcp:647) POOLREQ message — 3-byte header (Message Length + Message Type) + the rest of
// the message (payload-offset, time, xid) kept as payload hex. Byte-perfect round-trip.
test('DHCPFO POOLREQ: header + payload + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('dhcpfo/poolreq').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'dhcpfo'])
    const fo: any = Layer(decoded, 'dhcpfo').data
    assert.strictEqual(fo.length, 12, 'total message length incl the 2-byte length field')
    assert.strictEqual(fo.type, 1, 'POOLREQ')
    // payload = payload-offset (0x0c) + time (0x60000000) + xid (0x00000001)
    assert.strictEqual(fo.payload, '0c6000000000000001', 'payload after the message type')
})

// Crafting: a minimal POOLRESP (type 2, empty payload) with the Length auto-computed from the (empty)
// payload — the minimal 3-byte header must re-encode byte-identically.
test('DHCPFO faithfully encodes a crafted POOLRESP and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.2', dip: '192.0.2.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 647}},
        {id: 'dhcpfo', data: {type: 2}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    // 3 bytes of dhcpfo payload is below the match guard (8 bytes), so it falls through to raw — assert
    // the crafted bytes and the auto-computed Length directly, and round-trip byte-for-byte.
    const encoded: string = (await codec.encode(decoded)).packet.toString('hex')
    assert.strictEqual(encoded, packet.toString('hex'), 'byte-perfect')
    assert.ok(packet.toString('hex').endsWith('000302'), 'auto-computed Length 3 (header only) + type 2')
})

// honor-else-derive Length: a crafted CONNECT supplies an explicit Length — it must be honored verbatim
// (not overwritten by the derived value) so a message that carries any Length round-trips.
test('DHCPFO honors an explicitly supplied Length (does not derive over it)', async (): Promise<void> => {
    // payload: payload-offset 0x0c, time 0, xid 5 => 9 bytes. Length = 3 + 9 = 12.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 647, dstport: 51000}},
        {id: 'dhcpfo', data: {length: 12, type: 5, payload: '0c0000000000000005'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'dhcpfo'])
    const fo: any = Layer(decoded, 'dhcpfo').data
    assert.strictEqual(fo.type, 5, 'CONNECT')
    assert.strictEqual(fo.length, 12, 'supplied Length honored')
    assert.strictEqual(fo.payload, '0c0000000000000005', 'payload')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a short (< 8 byte) TCP/647 payload must NOT be claimed as DHCPFO (falls through to raw); and
// a truncated DHCPFO message must survive decode without throwing.
test('DHCPFO rejects a sub-header-length port-647 payload, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 647}},
        // 5 bytes — below the 8-byte match guard; no-signature bytes, not any registered content heuristic
        {id: 'raw', data: {data: '000c010c60'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'dhcpfo'), 'sub-header payload must not be claimed as DHCPFO')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('dhcpfo/poolreq').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})

// Protocol-specific edge: two DHCPFO messages pipelined in one TCP segment. The first message is bounded
// by its Length, so its payload does NOT swallow the trailing message; the trailing bytes fall through to
// raw (a leaf header advances only over its own message and does not re-match itself). Byte-for-byte.
test('DHCPFO pipelining: the first message is bounded by its Length; the trailing message falls through to raw', async (): Promise<void> => {
    const firstPayload: string = '0c6000000000000001'                  // 9-byte payload => length 12
    const first: string = '000c01' + firstPayload                      // 12-byte POOLREQ
    const second: string = '000c02' + '0c6000000000000002'             // 12-byte POOLRESP
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 647, dstport: 51000}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'dhcpfo', 'raw'])
    const fo: any = Layer(decoded, 'dhcpfo').data
    assert.strictEqual(fo.type, 1, 'first is POOLREQ')
    assert.strictEqual(fo.payload, firstPayload, 'payload bounded by its Length — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing POOLRESP left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
