import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'

// mDNS reuses the DNS wire format; the codec is a thin subclass on UDP 5353. Real avahi capture. RFC 6762.
test('mDNS query: DNS-format questions decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('mdns/query').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'mdns'])
    const mdns: any = Layer(decoded, 'mdns').data
    assert.strictEqual(mdns.qdcount, 2)
    assert.strictEqual(mdns.questions[0].name.value, '2.0.20.172.in-addr.arpa', 'reverse-PTR question')
})

// The response carries 5 answers with compression pointers AND the cache-flush bit (top bit of CLASS =
// 0x8001). Storing CLASS as its full 16-bit value preserves the cache-flush bit for a byte-perfect
// round-trip — the key thing mDNS layers on top of DNS.
test('mDNS response: cache-flush bit + compression preserved, byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('mdns/response').buffer)
    const mdns: any = Layer(decoded, 'mdns').data
    assert.strictEqual(mdns.flags.qr, true, 'a response')
    assert.strictEqual(mdns.ancount, 5)
    assert.strictEqual(mdns.answers[0].name.value, 'testhost._http._tcp.local')
    // 0x8001 = cache-flush bit (0x8000) | IN (0x0001) — preserved as the full 16-bit CLASS.
    assert.strictEqual(mdns.answers[0].class, 0x8001, 'cache-flush bit preserved in the record CLASS')
})

// Negative / crafting: mDNS is DNS with a QU (unicast-response) bit in the top of QCLASS. Craft a query
// with QU set (qclass 0x8001) and confirm the full 16-bit class round-trips.
test('mDNS faithfully encodes a crafted query with the QU (unicast-response) bit set', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:fb', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '224.0.0.251', protocol: 17}},
        {id: 'udp', data: {srcport: 5353, dstport: 5353}},
        {id: 'mdns', data: {
            id: 0,
            flags: {qr: false, opcode: 0, aa: false, tc: false, rd: false, ra: false, z: false, ad: false, cd: false, rcode: 0},
            qdcount: 1, ancount: 0, nscount: 0, arcount: 0,
            questions: [{name: {value: 'host.local', raw: ''}, qtype: 1, qclass: 0x8001}],
            answers: [], authorities: [], additionals: []
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const mdns: any = Layer(decoded, 'mdns').data
    assert.strictEqual(mdns.questions[0].name.value, 'host.local')
    assert.strictEqual(mdns.questions[0].qclass, 0x8001, 'QU bit + IN class round-trips')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// A real DNS response (srcport 53) sent to a client that happens to use port 5353 must NOT be mislabeled
// mDNS just because UDP produces its destination-port key first. mDNS never uses port 53. (Critic finding.)
test('a DNS response to client port 5353 decodes as dns, not mdns', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 53, dstport: 5353}},
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
