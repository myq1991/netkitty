import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertLayers, AssertDecodeSurvives, Layer, Decode, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'

test('IPv6 with Hop-by-Hop options header: field decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ipv6/hopbyhop-icmpv6').buffer)
    AssertLayers(decoded, ['eth', 'ipv6', 'ipv6-hopopt', 'icmpv6'])
    const ipv6: any = Layer(decoded, 'ipv6').data
    assert.strictEqual(ipv6.version, 6)
    assert.strictEqual(ipv6.nxt, 0, 'next header = hop-by-hop options')
    assert.strictEqual(ipv6.sip, 'fe80:0000:0000:0000:d754:0b32:a0b0:3646')
    assert.strictEqual(ipv6.dip, 'ff02:0000:0000:0000:0000:0000:0000:0016')
})

test('IPv6 with Segment Routing extension header: unsupported extension falls to raw (current behavior)', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ipv6/segment-routing').buffer)
    AssertLayers(decoded, ['eth', 'ipv6', 'raw'])
})

// The dispatch table normalizes IPv4 `protocol` and IPv6 `nxt` into a shared
// 'ipproto:' namespace, so TCP (registered under ipproto:6) resolves above IPv6.
test('IPv6 + TCP: TCP layer decoded above IPv6 (no extension header present)', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ipv6/tcp').buffer)
    AssertLayers(decoded, ['eth', 'ipv6', 'tcp'])
})

// BUG #1 (REAL) — IPv6HopByHopOptions.ts:522 encodes the Endpoint Identification option
// (type 138 / 0x8A, per the source comments at :18 and :331) with `new TLV(0x0C, ...)`.
// 0x0C is the ILNP-Nonce tag copied from the previous switch case, not the 0x8A that the
// decoder reads at :453. Decoding this packet yields an 'Endpoint-Identification' item, but
// re-encoding rewrites the option type byte 0x8A -> 0x0C, so the packet is not reproduced
// byte-for-byte. Correct behavior: Endpoint Identification must encode as option type 0x8A
// and the decode->encode round-trip must reproduce the original bytes.
test('IPv6 Hop-by-Hop Endpoint Identification option: round-trip must preserve type 0x8A', async (): Promise<void> => {
    const buffer: Buffer = LoadPacket('ipv6/hopopt-endpoint-id').buffer
    const decoded: CodecDecodeResult[] = await Decode(buffer)
    AssertLayers(decoded, ['eth', 'ipv6', 'ipv6-hopopt'])
    const hop: any = Layer(decoded, 'ipv6-hopopt').data
    const eid: any = hop.items.find((item: any): boolean => item.type === 'Endpoint-Identification')
    assert.ok(eid, 'Endpoint Identification option (type 0x8A) must decode')
    assert.strictEqual(eid.id.toLowerCase(), '000102030405060708090a0b0c0d0e0f')
    // Fails today: encode emits 0x0C (ILNP-Nonce) instead of 0x8A for this option.
    await AssertRoundTrip(buffer)
})

// BUG #2 (REAL, encode path) — IPv6HopByHopOptions.ts does not pad the options area to an
// 8-octet boundary on encode (RFC 8200 §4.3: an extension header is an integral multiple of
// 8 octets; the options area = HdrExtLen*8 + 6 bytes). The decoder at :372 additionally uses
// `len*8 + 7` (one byte too many), but its fallback loop self-corrects for well-formed packets,
// so the observable defect is the missing alignment padding on encode. When the encoded options
// do not total a multiple of 8, the encoder emits a short header while the len field still
// claims (len+1)*8 bytes, so the next header's bytes leak into the hop-by-hop options.
test('IPv6 Hop-by-Hop options: encoder must pad the options area to an 8-octet boundary', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await Decode(LoadPacket('ipv6/hopbyhop-icmpv6').buffer)
    const hop: any = Layer(decoded, 'ipv6-hopopt').data
    // Drop the trailing PadN so only the 4-byte Router-Alert option remains: the options area
    // is then 4 bytes and the header is 6 bytes -> NOT an 8-octet multiple.
    hop.items = hop.items.filter((item: any): boolean => item.type !== 'PadN')
    hop.len = 0 // exercise the encoder's length-recompute path
    const encoded = await codec.encode(decoded)
    const redecoded: CodecDecodeResult[] = await Decode(encoded.packet)
    const rehop: any = Layer(redecoded, 'ipv6-hopopt').data
    // Correct: the encoder inserts PadN, keeping the header 8-octet aligned; no foreign byte
    // leaks in as an option and the following ICMPv6 (MLDv2, type 143) stays intact.
    const leaked: boolean = rehop.items.some((item: any): boolean => typeof item.type === 'number')
    assert.ok(!leaked, 'no following-header byte should leak into the hop-by-hop options')
    const icmpv6: any = Layer(redecoded, 'icmpv6').data
    assert.strictEqual(icmpv6.type, 143, 'ICMPv6 (MLDv2) must remain intact after re-encode')
})

// RFC 8200 §4.2: Pad1 (type 0) is a single octet with no Length/Value. An interior Pad1 must
// be decoded as such and must not desync the option stream (the old node-tlv parser read a
// length octet after every type, mis-parsing interior Pad1). Also exercises the options-area
// length (len*8+6) and the bounded, never-throwing walker.
test('IPv6 Hop-by-Hop interior Pad1: options decode without desync + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ipv6/hopopt-pad1').buffer)
    AssertLayers(decoded, ['eth', 'ipv6', 'ipv6-hopopt', 'icmpv6'])
    const hop: any = Layer(decoded, 'ipv6-hopopt').data
    assert.deepStrictEqual(hop.items.map((it: any): string => it.type), ['Router-Alert', 'Pad1', 'Pad1'])
    assert.strictEqual(Layer(decoded, 'icmpv6').data.type, 143, 'ICMPv6 must stay intact after interior Pad1')
})

test('IPv6 Hop-by-Hop truncated at every length: decode never throws', async (): Promise<void> => {
    const full: Buffer = LoadPacket('ipv6/hopopt-pad1').buffer
    for (let n: number = 14; n < full.length; n++) {
        await AssertDecodeSurvives(full.subarray(0, n))
    }
})
