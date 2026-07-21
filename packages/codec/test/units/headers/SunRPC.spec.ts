import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// The portmap GETPORT CALL body after the four identity words: AUTH_NULL cred + verf (flavor 0, len 0
// each) then the GETPORT args {program 100005, version 1, protocol 17, port 0}.
const CALL_BODY: string = '00000000000000000000000000000000000186a5000000010000001100000000'

// SunRPC over UDP (udp:111) — portmap GETPORT CALL. The RPC message is the whole datagram (no prefix).
test('SunRPC UDP: xid + CALL identity + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('sunrpc/portmap-getport-udp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'sunrpc'])
    const rpc: any = Layer(decoded, 'sunrpc').data
    assert.strictEqual(rpc.xid, 'deadbeef', 'transaction id')
    assert.strictEqual(rpc.msgType, 0, 'CALL')
    assert.strictEqual(rpc.rpcVersion, 2, 'RPC version 2')
    assert.strictEqual(rpc.program, 100000, 'portmap program')
    assert.strictEqual(rpc.programVersion, 2, 'program version')
    assert.strictEqual(rpc.procedure, 3, 'GETPORT')
    assert.strictEqual(rpc.body, CALL_BODY, 'cred + verf + GETPORT args kept verbatim')
    assert.strictEqual(rpc.lastFragment, undefined, 'no Record Marking over UDP')
})

// SunRPC over TCP (tcp:111) — same CALL with a 4-byte Record Marking prefix (last-fragment + length 56).
test('SunRPC TCP: Record Marking + CALL identity + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('sunrpc/portmap-getport-tcp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'sunrpc'])
    const rpc: any = Layer(decoded, 'sunrpc').data
    assert.strictEqual(rpc.lastFragment, true, 'last-fragment flag set')
    assert.strictEqual(rpc.fragmentLength, 56, 'fragment length = RPC message bytes')
    assert.strictEqual(rpc.xid, 'deadbeef', 'transaction id')
    assert.strictEqual(rpc.msgType, 0, 'CALL')
    assert.strictEqual(rpc.program, 100000, 'portmap program')
    assert.strictEqual(rpc.procedure, 3, 'GETPORT')
    assert.strictEqual(rpc.body, CALL_BODY, 'cred + verf + GETPORT args kept verbatim')
})

// honor-else-derive over TCP: a crafted CALL with no fragmentLength supplied — it is derived as the
// encoded RPC message length; the last-fragment flag is honored; both directions round-trip.
test('SunRPC TCP derives the Record Marking fragment length when not supplied', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 111}},
        {id: 'sunrpc', data: {lastFragment: true, xid: 'cafebabe', msgType: 0, rpcVersion: 2, program: 100000, programVersion: 2, procedure: 0, body: ''}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'sunrpc'])
    const rpc: any = Layer(decoded, 'sunrpc').data
    assert.strictEqual(rpc.lastFragment, true, 'last-fragment flag honored')
    assert.strictEqual(rpc.fragmentLength, 24, 'derived length = xid + msgType + 4 identity words = 24')
    assert.strictEqual(rpc.procedure, 0, 'NULL procedure')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted TCP CALL supplies an explicit (lying) fragmentLength — it must be honored
// verbatim, not overwritten by the derived value.
test('SunRPC TCP honors an explicitly supplied fragment length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 111}},
        {id: 'sunrpc', data: {lastFragment: false, fragmentLength: 999, xid: '00000001', msgType: 0, rpcVersion: 2, program: 100000, programVersion: 2, procedure: 3, body: ''}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const rpc: any = Layer(decoded, 'sunrpc').data
    assert.strictEqual(rpc.lastFragment, false, 'last-fragment flag honored')
    assert.strictEqual(rpc.fragmentLength, 999, 'supplied fragment length honored (a crafted frame may lie)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A REPLY (msgType 1) keeps its whole body verbatim from message offset 8 — the CALL identity words are
// not structured — and round-trips over UDP.
test('SunRPC UDP REPLY keeps the whole body verbatim (no CALL identity)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 111, dstport: 40000}},
        // REPLY: xid + msgType(1) then reply body (MSG_ACCEPTED, AUTH_NULL verf, SUCCESS, port 635)
        {id: 'sunrpc', data: {xid: 'deadbeef', msgType: 1, body: '0000000000000000000000000000027b'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'sunrpc'])
    const rpc: any = Layer(decoded, 'sunrpc').data
    assert.strictEqual(rpc.msgType, 1, 'REPLY')
    assert.strictEqual(rpc.rpcVersion, undefined, 'CALL identity not structured for a REPLY')
    assert.strictEqual(rpc.body, '0000000000000000000000000000027b', 'whole reply body kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/111 payload whose Message Type is neither CALL nor REPLY must NOT be claimed as SunRPC
// (falls through to raw); and truncated / garbage RPC payloads must survive decode without throwing.
test('SunRPC rejects a non-CALL/REPLY Message Type on port 111, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 111}},
        // xid then Message Type 7 (neither CALL nor REPLY)
        {id: 'raw', data: {data: 'deadbeef00000007cccccccc'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'sunrpc'), 'invalid Message Type must not be claimed as SunRPC')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    // Truncated well-formed fixtures must not throw.
    const udp: Buffer = LoadPacket('sunrpc/portmap-getport-udp').buffer
    await AssertDecodeSurvives(udp.subarray(0, udp.length - 5))
    const tcp: Buffer = LoadPacket('sunrpc/portmap-getport-tcp').buffer
    await AssertDecodeSurvives(tcp.subarray(0, tcp.length - 30))
})
