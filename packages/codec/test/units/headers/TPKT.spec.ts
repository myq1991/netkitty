import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Ethernet + IPv4 + TCP(dstport 102) scaffolding shared by the crafted cases below.
const ETH: CodecDecodeResult = {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}} as any
const IPV4: CodecDecodeResult = {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}} as any
const TCP102: CodecDecodeResult = {id: 'tcp', data: {srcport: 50000, dstport: 102}} as any

// TPKT (RFC 1006, tcp:102) + COTP DT (ISO 8073 / X.224) carrying opaque ISO Session/MMS user data. The
// MMS-stack framing layers of IEC 61850. `pduType` is stored as the FULL PDU-Type octet (DT = 0xF0 = 240).
test('TPKT + COTP DT: framing decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tpkt/cotp-dt').buffer)
    // A fully-contained DT+EOT TPDU now exposes its user data as a child layer instead of keeping it in
    // cotp.data; here the ISO-Session/MMS payload (first byte 0x01, not an S7comm 0x32) is claimed by no
    // registered upper header yet, so it falls to a trailing raw layer.
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tpkt', 'cotp', 'raw'])
    const tpkt: any = Layer(decoded, 'tpkt').data
    assert.strictEqual(tpkt.version, 3, 'TPKT version is always 3')
    assert.strictEqual(tpkt.reserved, 0)
    assert.strictEqual(tpkt.length, 22, 'TPKT Length spans the whole PDU: 4 (header) + 18 (COTP)')
    const cotp: any = Layer(decoded, 'cotp').data
    assert.strictEqual(cotp.li, 2, 'Length Indicator = header octets after LI (PDU Type + EOT/TPDU-NR)')
    assert.strictEqual(cotp.pduType, 240, 'DT stored as the full octet 0xF0 = 240')
    assert.strictEqual(cotp.eot, true, 'EOT (end of TSDU) set')
    assert.strictEqual(cotp.tpduNr, 0)
    assert.strictEqual(cotp.headerRest, '', 'a DT TPDU structures its whole header, so no verbatim rest')
    assert.strictEqual(cotp.data, '', 'DT+EOT user data is exposed as a child layer, not kept in cotp.data')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, '0100010061093007020103a0020500', 'ISO Session/MMS user data now in the child raw layer')
})

// A non-DT TPDU (CR, Connect Request, 0xE0) keeps its type-specific header verbatim as `headerRest`
// (bounded by LI) plus any user data — proving the non-DT path round-trips byte-for-byte.
test('COTP CR (Connect Request) keeps its type-specific header verbatim and round-trips', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        ETH, IPV4, TCP102,
        {id: 'tpkt', data: {version: 3, reserved: 0}}, // Length omitted → derived
        {id: 'cotp', data: {li: 7, pduType: 0xe0, headerRest: 'aabbccddeeff', data: 'deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    // A CR now also exposes its user data as a child (it carries the RDP Negotiation); this crafted
    // non-RDP data (deadbeef) is claimed by no upper header, so it falls to a trailing raw layer.
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tpkt', 'cotp', 'raw'])
    const cotp: any = Layer(decoded, 'cotp').data
    assert.strictEqual(cotp.pduType, 0xe0, 'CR PDU Type preserved')
    assert.strictEqual(cotp.headerRest, 'aabbccddeeff', 'CR type-specific header kept verbatim')
    assert.strictEqual(cotp.data, '', 'CR user data is exposed as a child layer, not kept in cotp.data')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, 'deadbeef', 'non-RDP user data now in the child raw layer')
    assert.strictEqual(cotp.eot, false, 'EOT is meaningless (false) for a non-DT TPDU')
    // Derived TPKT Length = 4 (header) + 8 (COTP: LI + PDU Type + 6 header bytes + 4 data).
    assert.strictEqual(Layer(decoded, 'tpkt').data.length, 16, 'omitted TPKT Length derived from the stack above')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// TPKT Length is honor-else-derive: absent → derived from this layer + everything above; present → honored
// verbatim (a crafted frame may carry a lying Length, which is reproduced faithfully).
test('TPKT Length: derived when absent, honored verbatim when supplied', async (): Promise<void> => {
    // Derive: no Length supplied.
    const {packet: derivedPacket}: CodecEncodeResult = await codec.encode([
        ETH, IPV4, TCP102,
        {id: 'tpkt', data: {version: 3, reserved: 0}},
        {id: 'cotp', data: {li: 2, pduType: 240, eot: false, tpduNr: 0, data: '11223344'}}
    ])
    const derived: CodecDecodeResult[] = await codec.decode(derivedPacket)
    // 4 (TPKT) + 3 (COTP header: LI + PDU Type + EOT/TPDU-NR) + 4 (data) = 11.
    assert.strictEqual(Layer(derived, 'tpkt').data.length, 11, 'derived TPKT Length')

    // Honor: a deliberately over-large Length is reproduced verbatim, not recomputed.
    const {packet: honoredPacket}: CodecEncodeResult = await codec.encode([
        ETH, IPV4, TCP102,
        {id: 'tpkt', data: {version: 3, reserved: 0, length: 999}},
        {id: 'cotp', data: {li: 2, pduType: 240, eot: false, tpduNr: 0, data: '11223344'}}
    ])
    const honored: CodecDecodeResult[] = await codec.decode(honoredPacket)
    assert.strictEqual(Layer(honored, 'tpkt').data.length, 999, 'a supplied Length is honored verbatim')
    assert.strictEqual((await codec.encode(honored)).packet.toString('hex'), honoredPacket.toString('hex'), 'lying Length round-trips')
})

// Robustness: a frame truncated inside the COTP user data must decode best-effort (never throw) and
// round-trip; and a payload that is not TPKT (wrong port, or Version != 3) must NOT be claimed as tpkt.
test('TPKT truncation survives; non-TPKT payloads are not claimed', async (): Promise<void> => {
    const full: Buffer = LoadPacket('tpkt/cotp-dt').buffer
    const truncated: Buffer = full.subarray(0, full.length - 8) // cut into the COTP user data
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(truncated)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tpkt', 'cotp'])
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), truncated.toString('hex'), 'truncated frame round-trips')

    // A TPKT-looking payload on a non-102 TCP port must not be claimed (matchKeys = tcpport:102 only).
    const {packet: offPort}: CodecEncodeResult = await codec.encode([
        ETH, IPV4, {id: 'tcp', data: {srcport: 40000, dstport: 80}} as any,
        {id: 'raw', data: {data: '0300001602f080aabbcc'}}
    ])
    const offPortDecoded: CodecDecodeResult[] = await codec.decode(offPort)
    assert.ok(!offPortDecoded.some((l: CodecDecodeResult): boolean => l.id === 'tpkt'), 'off-port payload must not be tpkt')
    assert.strictEqual(offPortDecoded[offPortDecoded.length - 1].id, 'raw')

    // On port 102 but with Version != 3: the content signature fails, so it falls through to raw.
    const {packet: badVersion}: CodecEncodeResult = await codec.encode([
        ETH, IPV4, TCP102,
        {id: 'raw', data: {data: '0500001602f080aabbcc'}}
    ])
    const badVersionDecoded: CodecDecodeResult[] = await codec.decode(badVersion)
    assert.ok(!badVersionDecoded.some((l: CodecDecodeResult): boolean => l.id === 'tpkt'), 'Version != 3 must not be tpkt')
})

// COTP is an unkeyed content-heuristic child gated on prev.id === 'tpkt'. A raw TCP payload that happens
// to look like a COTP DT TPDU must NOT be claimed as cotp when there is no TPKT parent.
test('COTP only matches under TPKT (not a bare TCP payload)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        ETH, IPV4, {id: 'tcp', data: {srcport: 40000, dstport: 9999}} as any,
        {id: 'raw', data: {data: '02f0800100010061'}} // looks like a COTP DT header, but no TPKT parent
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'cotp'), 'COTP must require a TPKT parent')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
})
