import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// The NFS v3 GETATTR CALL body after the four identity words: AUTH_NULL cred + verf (flavor 0, len 0
// each) then the GETATTR args nfs_fh3 {length 8, handle 0102030405060708}.
const CALL_BODY: string = '00000000000000000000000000000000000000080102030405060708'

// NFS over UDP (udp:2049) — v3 GETATTR CALL. The RPC message is the whole datagram (no prefix).
test('NFS UDP: xid + CALL identity (program 100003) + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('nfs/getattr-udp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'nfs'])
    const nfs: any = Layer(decoded, 'nfs').data
    assert.strictEqual(nfs.xid, 'deadbeef', 'transaction id')
    assert.strictEqual(nfs.msgType, 0, 'CALL')
    assert.strictEqual(nfs.rpcVersion, 2, 'RPC version 2')
    assert.strictEqual(nfs.program, 100003, 'NFS program')
    assert.strictEqual(nfs.programVersion, 3, 'NFS v3')
    assert.strictEqual(nfs.procedure, 1, 'GETATTR')
    assert.strictEqual(nfs.body, CALL_BODY, 'cred + verf + GETATTR args kept verbatim')
    assert.strictEqual(nfs.lastFragment, undefined, 'no Record Marking over UDP')
})

// NFS over TCP (tcp:2049) — a crafted CALL with a 4-byte Record Marking prefix and no fragmentLength
// supplied: it is derived as the encoded RPC message length; the last-fragment flag is honored.
test('NFS TCP derives the Record Marking fragment length when not supplied', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 2049}},
        {id: 'nfs', data: {lastFragment: true, xid: 'cafebabe', msgType: 0, rpcVersion: 2, program: 100003, programVersion: 3, procedure: 0, body: ''}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'nfs'])
    const nfs: any = Layer(decoded, 'nfs').data
    assert.strictEqual(nfs.lastFragment, true, 'last-fragment flag honored')
    assert.strictEqual(nfs.fragmentLength, 24, 'derived length = xid + msgType + 4 identity words = 24')
    assert.strictEqual(nfs.program, 100003, 'NFS program')
    assert.strictEqual(nfs.procedure, 0, 'NULL procedure')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted TCP CALL supplies an explicit (lying) fragmentLength — it must be honored
// verbatim, not overwritten by the derived value.
test('NFS TCP honors an explicitly supplied fragment length (does not derive over it)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 2049}},
        {id: 'nfs', data: {lastFragment: false, fragmentLength: 999, xid: '00000001', msgType: 0, rpcVersion: 2, program: 100003, programVersion: 3, procedure: 1, body: ''}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const nfs: any = Layer(decoded, 'nfs').data
    assert.strictEqual(nfs.lastFragment, false, 'last-fragment flag honored')
    assert.strictEqual(nfs.fragmentLength, 999, 'supplied fragment length honored (a crafted frame may lie)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A REPLY (msgType 1) keeps its whole body verbatim from message offset 8 — the CALL identity words are
// not structured — and round-trips over UDP.
test('NFS UDP REPLY keeps the whole body verbatim (no CALL identity)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.20', dip: '192.0.2.10', protocol: 17}},
        {id: 'udp', data: {srcport: 2049, dstport: 40000}},
        // REPLY: xid + msgType(1) then reply body (MSG_ACCEPTED, AUTH_NULL verf, SUCCESS, then NFS3_OK)
        {id: 'nfs', data: {xid: 'deadbeef', msgType: 1, body: '00000000000000000000000000000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'nfs'])
    const nfs: any = Layer(decoded, 'nfs').data
    assert.strictEqual(nfs.msgType, 1, 'REPLY')
    assert.strictEqual(nfs.rpcVersion, undefined, 'CALL identity not structured for a REPLY')
    assert.strictEqual(nfs.body, '00000000000000000000000000000000', 'whole reply body kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a UDP/2049 payload whose Message Type is neither CALL nor REPLY must NOT be claimed as NFS
// (falls through to raw); and a truncated well-formed fixture must survive decode without throwing.
test('NFS rejects a non-CALL/REPLY Message Type on port 2049, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 2049}},
        // xid then Message Type 7 (neither CALL nor REPLY)
        {id: 'raw', data: {data: 'deadbeef00000007cccccccc'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'nfs'), 'invalid Message Type must not be claimed as NFS')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    // Truncated well-formed fixture must not throw.
    const udp: Buffer = LoadPacket('nfs/getattr-udp').buffer
    await AssertDecodeSurvives(udp.subarray(0, udp.length - 5))
})
