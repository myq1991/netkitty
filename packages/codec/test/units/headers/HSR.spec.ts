import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// HSR (IEC 62439-3 Clause 5, EtherType 0x892F) inserts a 6-byte tag after the Ethernet header and then
// carries the ORIGINAL EtherType + payload. This fixture carries GOOSE (carried EtherType 0x88b8): the
// frame must decode [eth, hsr, goose] and round-trip byte-perfect.
test('HSR over GOOSE: field decode + byte-perfect round-trip + inner GOOSE dispatch', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('hsr/goose').buffer)
    AssertLayers(decoded, ['eth', 'hsr', 'goose'])
    const hsr: any = Layer(decoded, 'hsr').data
    assert.strictEqual(hsr.path, 1, 'Path = top 4 bits of the first word')
    assert.strictEqual(hsr.lsduSize, 0x099, 'LSDUsize = low 12 bits of the first word')
    assert.strictEqual(hsr.seqNr, 0x002a, 'SeqNr')
    assert.strictEqual(hsr.etherType, '88b8', 'carried EtherType stored as a lowercase 4-hex string')
})

// THE KEY TEST: the carried-EtherType field MUST be named `etherType` and stored exactly like VLAN,
// because GOOSE/SV/VLAN/ARP discriminate by reading prevCodecModule.instance.etherType. With carried
// EtherType 0x88b8 the inner layer MUST be goose — proving the field name drives inner dispatch. A wrong
// field name would make GOOSE read undefined and silently fall through to RawData.
test('HSR etherType-naming proof: carried 88b8 dispatches GOOSE over an HSR parent', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('hsr/goose').buffer)
    assert.strictEqual(decoded[1].id, 'hsr', 'HSR selected off Ethernet ethertype 0x892f')
    assert.strictEqual((Layer(decoded, 'hsr').data as any).etherType, '88b8')
    assert.ok(decoded.some((l: CodecDecodeResult): boolean => l.id === 'goose'), 'inner GOOSE dispatched via HSR.etherType')
    assert.notStrictEqual(decoded[2].id, 'rawdata', 'inner frame must NOT fall through to RawData')
})

// Crafted eth(892f) → hsr{etherType:'0800'} → ipv4: the carried EtherType 0x0800 must dispatch IPv4,
// and the whole stack must survive a decode → re-encode round-trip byte-for-byte.
test('HSR crafted over IPv4: encode → decode → re-encode is byte-identical', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:15:4e:00:01:04', smac: '00:11:22:33:44:55', etherType: '892f'}},
        {id: 'hsr', data: {path: 2, lsduSize: 0x20, seqNr: 7, etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 253}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'hsr', 'ipv4'])
    const hsr: any = Layer(decoded, 'hsr').data
    assert.strictEqual(hsr.path, 2)
    assert.strictEqual(hsr.lsduSize, 0x20)
    assert.strictEqual(hsr.seqNr, 7)
    assert.strictEqual(hsr.etherType, '0800', 'carried EtherType 0x0800 drives the IPv4 dispatch')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// The first 2 octets pack Path (4 bits) + LSDUsize (12 bits). path=5, lsduSize=0x123 must serialize to
// the word (5<<12)|0x123 = 0x5123 and decode back to the same split — proving the 4+12 bit boundary and
// that writeBits masks each field so they don't clobber each other in the shared window.
test('HSR Path/LSDUsize 4+12 bit split round-trips', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:15:4e:00:01:04', smac: '00:11:22:33:44:55', etherType: '892f'}},
        {id: 'hsr', data: {path: 5, lsduSize: 0x123, seqNr: 0, etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 253}}
    ])
    // Bytes 14-15 (right after the outer 0x892f at 12-13) are the packed Path/LSDUsize word.
    assert.strictEqual(packet.subarray(14, 16).toString('hex'), '5123', 'packed word = (5<<12)|0x123 = 0x5123')
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const hsr: any = Layer(decoded, 'hsr').data
    assert.strictEqual(hsr.path, 5)
    assert.strictEqual(hsr.lsduSize, 0x123)
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// VLAN-tagged HSR: like a VLAN tag, HSR is selected purely by the carrying layer's EtherType, with no
// restriction on which layer carries it. A VLAN (0x8100) whose inner EtherType is 0x892f must decode
// [eth, vlan, hsr, <inner>] and round-trip byte-perfect (mirrors VLAN's own parent-agnostic match).
test('HSR inside a VLAN: carried 0x892f under a VLAN tag dispatches HSR', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:15:4e:00:01:04', smac: '00:11:22:33:44:55', etherType: '8100'}},
        {id: 'vlan', data: {vlanId: 100, etherType: '892f'}},
        {id: 'hsr', data: {path: 1, lsduSize: 0x10, seqNr: 3, etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 253}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'vlan', 'hsr', 'ipv4'])
    assert.strictEqual((Layer(decoded, 'hsr').data as any).seqNr, 3)
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'VLAN-tagged HSR round-trips byte-perfect')
})

// Robustness: a frame truncated inside the HSR tag must decode without throwing and round-trip via the
// raw fallback; and a non-0x892f Ethernet frame must NOT be claimed as HSR.
test('HSR truncation survives; non-892f Ethernet is not claimed as HSR', async (): Promise<void> => {
    const full: Buffer = LoadPacket('hsr/goose').buffer
    // Cut mid-HSR-tag (14 eth + 3 of the 6-byte tag): decode must survive and round-trip the bytes.
    const truncated: Buffer = full.subarray(0, 17)
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(truncated)
    assert.strictEqual((await codec.encode(survived)).packet.toString('hex'), truncated.toString('hex'), 'truncated frame round-trips')

    // An ordinary IPv4 Ethernet frame (ethertype 0x0800) must never be selected as HSR.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:15:4e:00:01:04', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 253}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'hsr'), 'a non-892f frame must not decode as HSR')
})
