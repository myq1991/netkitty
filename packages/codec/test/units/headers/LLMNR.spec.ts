import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'

// Real LLMNR query (RFC 4795, DNS wire format) on UDP 5355 for "wpad" A. The codec is a thin DNS subclass.
test('LLMNR query: DNS-format question decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('llmnr/query').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'llmnr'])
    const llmnr: any = Layer(decoded, 'llmnr').data
    assert.strictEqual(llmnr.id, 0x2a1b)
    assert.strictEqual(llmnr.flags.qr, false, 'a query')
    assert.strictEqual(llmnr.qdcount, 1)
    assert.strictEqual(llmnr.questions[0].name.value, 'wpad')
    assert.strictEqual(llmnr.questions[0].qtype, 1, 'A')
})

// Negative / crafting: LLMNR is DNS with a QU-less header; craft a response with an answer and confirm
// the DNS-format encode round-trips through the subclass.
test('LLMNR faithfully encodes a crafted response', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:fc', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.5', dip: '10.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 5355, dstport: 55000}},
        {id: 'llmnr', data: {
            id: 0x2a1b,
            flags: {qr: true, opcode: 0, aa: false, tc: false, rd: false, ra: false, z: false, ad: false, cd: false, rcode: 0},
            qdcount: 1, ancount: 1, nscount: 0, arcount: 0,
            questions: [{name: {value: 'wpad', raw: ''}, qtype: 1, qclass: 1}],
            answers: [{name: {value: 'wpad', raw: ''}, type: 1, class: 1, ttl: 30, rdlength: 0, rdata: '0a000005'}],
            authorities: [], additionals: []
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const llmnr: any = Layer(decoded, 'llmnr').data
    assert.strictEqual(llmnr.flags.qr, true)
    assert.strictEqual(llmnr.answers[0].name.value, 'wpad')
    assert.strictEqual(llmnr.answers[0].rdata, '0a000005')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// A DNS response to a client port 5355 (srcport 53) must not be mislabeled llmnr. (Mirrors mDNS.)
test('a DNS response to client port 5355 decodes as dns, not llmnr', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 53, dstport: 5355}},
        {id: 'dns', data: {
            id: 0x1234,
            flags: {qr: true, opcode: 0, aa: false, tc: false, rd: false, ra: false, z: false, ad: false, cd: false, rcode: 0},
            qdcount: 0, ancount: 0, nscount: 0, arcount: 0,
            questions: [], answers: [], authorities: [], additionals: []
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'dns'])
})
