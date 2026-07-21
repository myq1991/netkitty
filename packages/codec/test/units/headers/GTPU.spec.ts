import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// GTP-U G-PDU (3GPP TS 29.281) on UDP 2152 tunneling an inner IPv4/ICMP packet. The inner IP is decoded
// RECURSIVELY (IPv4/IPv6 accept a GTP tunnel parent, matching by version nibble) — the L3 tunnel showcase.
test('GTP-U G-PDU: header + recursive inner IP decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('gtpu/gpdu-inner-icmp').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'gtp', 'ipv4', 'icmp'])
    const gtp: any = Layer(decoded, 'gtp').data
    assert.strictEqual(gtp.flags.version, 1, 'GTP version 1')
    assert.strictEqual(gtp.flags.pt, true, 'GTP (not GTP\') protocol type')
    assert.strictEqual(gtp.msgType, 0xff, 'G-PDU')
    assert.strictEqual(gtp.teid, '12345678')
    assert.strictEqual(gtp.optionalHeader, '', 'no optional header (E/S/PN clear)')
    // The inner IPv4 (second ip layer) is the tunneled user packet.
    const innerIp: CodecDecodeResult = decoded.filter((l: CodecDecodeResult): boolean => l.id === 'ipv4')[1]
    assert.ok(innerIp, 'inner IPv4 decoded through the tunnel')
})

// A non-G-PDU message (Echo Request, type 1) carries GTP Information Elements, NOT an inner IP. The
// codec must NOT mis-decode the IEs as an inner IP by the version nibble — GTP-U consumes them itself.
test('GTP-U non-G-PDU (Echo Request) does not mis-decode its IEs as inner IP', async (): Promise<void> => {
    // Craft an Echo Request (type 1) whose IE payload happens to start with 0x45 (would look like IPv4).
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 2152}},
        {id: 'gtp', data: {
            flags: {version: 1, pt: true, e: false, s: false, pn: false}, msgType: 1,
            teid: '00000000', optionalHeader: '', payload: '450e00'
        }}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'gtp'])
    assert.strictEqual((Layer(decoded, 'gtp').data as any).msgType, 1, 'Echo Request')
    assert.ok(!decoded.some((l: CodecDecodeResult, i: number): boolean => l.id === 'ipv4' && i > 3), 'no inner IPv4 mis-decoded from the IEs')
})

// Negative / crafting: build a G-PDU wrapping a crafted inner IPv4/UDP frame, confirm the recursion +
// the auto-computed GTP Length.
test('GTP-U faithfully encodes a crafted G-PDU over an inner IPv4/UDP packet', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 2152, dstport: 2152}},
        {id: 'gtp', data: {flags: {version: 1, pt: true, e: false, s: false, pn: false}, msgType: 0xff, teid: 'deadbeef', optionalHeader: '', payload: ''}},
        {id: 'ipv4', data: {sip: '192.168.5.1', dip: '192.168.5.2', protocol: 17}},
        {id: 'udp', data: {srcport: 5000, dstport: 5001}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'gtp', 'ipv4', 'udp'])
    assert.strictEqual((Layer(decoded, 'gtp').data as any).teid, 'deadbeef')
    assert.strictEqual((decoded.filter((l: CodecDecodeResult): boolean => l.id === 'ipv4')[1].data as any).dip, '192.168.5.2', 'inner IP decoded through the tunnel')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

test('GTP-U truncated mid inner-IP: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('gtpu/gpdu-inner-icmp').buffer
    await AssertDecodeSurvives(full.subarray(0, 44))
})
