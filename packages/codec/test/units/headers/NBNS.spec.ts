import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'

// Real NBNS name query (RFC 1002) on UDP 137 from samba nmblookup. DNS wire format + first-level name.
test('NBNS name query: first-level name decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('nbns/name-query').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'nbns'])
    const nbns: any = Layer(decoded, 'nbns').data
    assert.strictEqual(nbns.id, 0x5c2a)
    assert.strictEqual(nbns.flags.qr, false, 'a query')
    assert.strictEqual(nbns.qdcount, 1)
    // The 32-byte first-level-encoded label decodes to the readable NetBIOS name + suffix.
    assert.strictEqual(nbns.questions[0].name.value, 'WORKGROUP<00>')
    // The raw wire bytes (the encoded label) are preserved for the byte-perfect round-trip.
    assert.ok(nbns.questions[0].name.raw.startsWith('20464845'), 'raw = length 0x20 + first-level-encoded label')
    assert.strictEqual(nbns.questions[0].qtype, 0x20, 'NB (NetBIOS name) query type')
})

// Crafting from the readable value (no raw): the "NAME<XX>" form re-encodes to the 32-byte first-level
// label and round-trips. This exercises the writeName override's first-level ENCODE path.
test('NBNS crafted from a readable NetBIOS name re-encodes the first-level form', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.255', protocol: 17}},
        {id: 'udp', data: {srcport: 137, dstport: 137}},
        {id: 'nbns', data: {
            id: 0x1234,
            flags: {qr: false, opcode: 0, aa: false, tc: false, rd: true, ra: false, z: false, ad: false, cd: false, rcode: 0},
            qdcount: 1, ancount: 0, nscount: 0, arcount: 0,
            questions: [{name: {value: 'TESTPC<20>', raw: ''}, qtype: 0x20, qclass: 1}],
            answers: [], authorities: [], additionals: []
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const nbns: any = Layer(decoded, 'nbns').data
    assert.strictEqual(nbns.questions[0].name.value, 'TESTPC<20>', 'the file-server suffix 0x20 round-trips')
    // Re-encoding the decoded packet (which now carries raw) reproduces the exact same bytes.
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})
