import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'

// Real DNS query "A test.local" captured from dig against a local dnsmasq. RFC 1035.
test('DNS query: header + question decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('dns/query').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'dns'])
    const dns: any = Layer(decoded, 'dns').data
    assert.strictEqual(dns.id, 0x07e0)
    assert.strictEqual(dns.flags.qr, false, 'a query')
    assert.strictEqual(dns.flags.rd, true, 'recursion desired')
    assert.strictEqual(dns.qdcount, 1)
    assert.strictEqual(dns.ancount, 0)
    assert.strictEqual(dns.questions.length, 1)
    assert.strictEqual(dns.questions[0].name.value, 'test.local')
    assert.strictEqual(dns.questions[0].name.raw, '0474657374056c6f63616c00', 'uncompressed label sequence')
    assert.strictEqual(dns.questions[0].qtype, 1, 'A')
    assert.strictEqual(dns.questions[0].qclass, 1, 'IN')
})

// Real DNS response. The answer NAME is a COMPRESSION POINTER (0xc00c → offset 12) — the core test:
// its resolved value must be 'test.local' and its raw must be the 2 pointer bytes, round-tripping exactly.
test('DNS response: compression pointer resolves + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('dns/response').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'dns'])
    const dns: any = Layer(decoded, 'dns').data
    assert.strictEqual(dns.flags.qr, true, 'a response')
    assert.strictEqual(dns.flags.aa, true, 'authoritative')
    assert.strictEqual(dns.ancount, 1)
    const answer: any = dns.answers[0]
    assert.strictEqual(answer.name.value, 'test.local', 'compression pointer resolved to the question name')
    assert.strictEqual(answer.name.raw, 'c00c', 'the raw name is the 2-byte pointer, not the expanded labels')
    assert.strictEqual(answer.type, 1, 'A')
    assert.strictEqual(answer.ttl, 0)
    assert.strictEqual(answer.rdlength, 4)
    assert.strictEqual(answer.rdata, '01020304', 'RDATA = 1.2.3.4, kept as raw hex')
})

// Negative / crafting: encode is a faithful executor. Build a response with an answer whose name is
// crafted from `value` alone (no raw) — encode produces an UNCOMPRESSED name — plus a hand-set rdata.
test('DNS faithfully encodes a crafted response, building an uncompressed name from value', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 53, dstport: 40000}},
        {id: 'dns', data: {
            id: 0x1234,
            flags: {qr: true, opcode: 0, aa: true, tc: false, rd: false, ra: false, z: false, ad: false, cd: false, rcode: 0},
            qdcount: 0, ancount: 1, nscount: 0, arcount: 0,
            questions: [],
            answers: [{name: {value: 'a.example', raw: ''}, type: 1, class: 1, ttl: 300, rdlength: 0, rdata: '08080808'}]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const dns: any = Layer(decoded, 'dns').data
    assert.strictEqual(dns.id, 0x1234)
    assert.strictEqual(dns.answers.length, 1)
    // The crafted name was emitted uncompressed and decodes back to the same dotted value + raw labels.
    assert.strictEqual(dns.answers[0].name.value, 'a.example')
    assert.strictEqual(dns.answers[0].name.raw, '0161076578616d706c6500', 'uncompressed: 1"a" 7"example" 0')
    assert.strictEqual(dns.answers[0].ttl, 300)
    assert.strictEqual(dns.answers[0].rdata, '08080808')
    assert.strictEqual(dns.answers[0].rdlength, 4, 'rdlength derived from rdata length')
})

test('DNS truncated mid-answer: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('dns/response').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 8))
})

// A compression pointer that points at itself must not hang the decoder (loop protection).
test('DNS self-referential compression pointer does not loop', async (): Promise<void> => {
    // eth+ipv4+udp then a DNS header claiming 1 question whose name is a pointer to offset 12 (itself).
    const dnsHex: string = '00010000' + '0001' + '0000' + '0000' + '0000' + 'c00c' + '00010001'
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 53, dstport: 40000}},
        {id: 'raw', data: {data: dnsHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(decoded.some((l: CodecDecodeResult): boolean => l.id === 'dns'), 'decodes as DNS without hanging')
})
