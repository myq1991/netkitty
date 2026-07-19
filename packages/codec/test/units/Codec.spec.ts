import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer} from '../lib/RoundTrip'
import {Codec} from '../../src/lib/codec/Codec'
import {ARP} from '../../src/lib/codec/PacketHeaders'
import {BaseHeader} from '../../src/lib/codec/abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../src/lib/schema/ProtocolJSONSchema'
import {CodecDecodeResult} from '../../src/lib/codec/types/CodecDecodeResult'

test('unknown ethertype falls to raw layer + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('codec/unknown-ethertype').buffer)
    AssertLayers(decoded, ['eth', 'raw'])
})

test('garbage input: decode never fails, everything lands in eth+raw', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(Buffer.alloc(60, 0xff))
    AssertLayers(decoded, ['eth', 'raw'])
})

test('custom codec with same PROTOCOL_ID overrides the built-in one', async (): Promise<void> => {
    class CustomARP extends ARP {
        public readonly name: string = 'Custom ARP'
    }

    const codec: Codec = new Codec([CustomARP as any])
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('arp/baseline').buffer)
    const arp: CodecDecodeResult = Layer(decoded, 'arp')
    assert.strictEqual(arp.name, 'Custom ARP')
})

// A custom codec that declares a demux key registers in the dispatch table and
// is reachable during decode (the RawData catch-all no longer shadows it).
test('newly added custom codec is reachable during decode', async (): Promise<void> => {
    class Proto88B5 extends BaseHeader {
        public readonly SCHEMA: ProtocolJSONSchema = {
            type: 'object',
            properties: {}
        }
        public readonly id: string = 'proto88b5'
        public readonly name: string = 'Experimental 0x88B5'
        public readonly nickname: string = 'EXP1'
        public readonly matchKeys: string[] = ['ethertype:88b5']

        public match(): boolean {
            if (!this.prevCodecModule) return false
            return this.prevCodecModule.instance.etherType.getValue() === '88b5'
        }
    }

    const codec: Codec = new Codec([Proto88B5 as any])
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('codec/unknown-ethertype').buffer)
    Layer(decoded, 'proto88b5')
})

// Regression: the demux dispatch must confirm even a single-registrant bucket with the codec's own
// match(). 'ipproto:0' is produced by BOTH an IPv4 protocol=0 and an IPv6 next-header=0, but IPv6
// Hop-by-Hop options are the sole registrant; without running its match() (which requires an IPv6
// parent) an IPv4 protocol=0 packet was wrongly decoded as a Hop-by-Hop header.
// The packet is deliberately malformed — building it via encode also exercises the "encode is a
// faithful executor, it can construct any illegal packet" contract — and it must still round-trip.
test('IPv4 protocol=0 must not misroute into IPv6 Hop-by-Hop (single-bucket match() is enforced)', async (): Promise<void> => {
    const codec: Codec = new Codec()
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {protocol: 0}}
    ])
    //Append trailing bytes that the buggy dispatch would have eaten as a Hop-by-Hop header.
    const malformed: Buffer = Buffer.concat([packet, Buffer.from('0102030405060708', 'hex')])

    const decoded: CodecDecodeResult[] = await AssertRoundTrip(malformed)
    assert.ok(decoded.some((layer: CodecDecodeResult): boolean => layer.id === 'ipv4'), 'IPv4 layer present')
    assert.ok(
        decoded.every((layer: CodecDecodeResult): boolean => layer.id !== 'ipv6-hopopt'),
        'IPv4 protocol=0 must not decode into an IPv6 Hop-by-Hop header'
    )
})

// M1②: a codec may register in BOTH its demux bucket AND the heuristic fallback (heuristicFallback),
// so a content-signed protocol takes the O(1) bucket on its well-known key yet is still recognized off
// it — the framework guarantee that later lets TLS keep working on non-443 ports.
class SignedDual extends BaseHeader {
    public readonly SCHEMA: ProtocolJSONSchema = {type: 'object', properties: {}}
    public readonly id: string = 'signed-dual'
    public readonly name: string = 'Signed Dual'
    public readonly nickname: string = 'DUAL'
    public readonly matchKeys: string[] = ['ethertype:88b5']
    public readonly heuristicFallback: boolean = true
    public match(): boolean {
        return !!this.prevCodecModule && this.prevCodecModule.id === 'eth'
    }
}
function ethFrame(etherTypeHex: string, payloadHex: string): Buffer {
    return Buffer.from('ffffffffffff' + '001122334455' + etherTypeHex + payloadHex, 'hex')
}

test('dual registration: a heuristicFallback codec is reachable via its demux bucket (fast path)', async (): Promise<void> => {
    const codec: Codec = new Codec([SignedDual as any])
    const decoded: CodecDecodeResult[] = await codec.decode(ethFrame('88b5', '01020304'))
    assert.ok(decoded.some((l: CodecDecodeResult): boolean => l.id === 'signed-dual'), 'reached via ethertype:88b5 bucket')
})

test('dual registration: the same codec is still reached off its key via the heuristic fallback', async (): Promise<void> => {
    const codec: Codec = new Codec([SignedDual as any])
    // etherType 0x9999 has no bucket → must fall through to the heuristic list, where the dual codec also lives.
    const decoded: CodecDecodeResult[] = await codec.decode(ethFrame('9999', '01020304'))
    assert.ok(decoded.some((l: CodecDecodeResult): boolean => l.id === 'signed-dual'), 'reached off-key via heuristic fallback')
})

// Boundary: a keyed codec WITHOUT heuristicFallback (the default) is NOT in the heuristic list, so it
// is only reachable via its exact demux key — behavior unchanged from before M1②.
test('a keyed codec without heuristicFallback is only reachable via its key', async (): Promise<void> => {
    class KeyedOnly extends BaseHeader {
        public readonly SCHEMA: ProtocolJSONSchema = {type: 'object', properties: {}}
        public readonly id: string = 'keyed-only'
        public readonly name: string = 'Keyed Only'
        public readonly nickname: string = 'KO'
        public readonly matchKeys: string[] = ['ethertype:88b6']
        public match(): boolean {
            return !!this.prevCodecModule && this.prevCodecModule.id === 'eth'
        }
    }
    const codec: Codec = new Codec([KeyedOnly as any])
    const onKey: CodecDecodeResult[] = await codec.decode(ethFrame('88b6', '01020304'))
    assert.ok(onKey.some((l: CodecDecodeResult): boolean => l.id === 'keyed-only'), 'reached on its key')
    const offKey: CodecDecodeResult[] = await codec.decode(ethFrame('9999', '01020304'))
    assert.ok(offKey.every((l: CodecDecodeResult): boolean => l.id !== 'keyed-only'), 'NOT reachable off its key (no fallback)')
})

// matchPriority orders multiple candidates in a bucket deterministically (higher first), regardless of
// registration order.
test('matchPriority: within a bucket the higher-priority codec wins even if registered later', async (): Promise<void> => {
    class LoPri extends BaseHeader {
        public readonly SCHEMA: ProtocolJSONSchema = {type: 'object', properties: {}}
        public readonly id: string = 'lo-pri'
        public readonly name: string = 'Lo'
        public readonly nickname: string = 'LO'
        public readonly matchKeys: string[] = ['ethertype:88b7']
        public readonly matchPriority: number = 0
        public match(): boolean { return !!this.prevCodecModule && this.prevCodecModule.id === 'eth' }
    }
    class HiPri extends BaseHeader {
        public readonly SCHEMA: ProtocolJSONSchema = {type: 'object', properties: {}}
        public readonly id: string = 'hi-pri'
        public readonly name: string = 'Hi'
        public readonly nickname: string = 'HI'
        public readonly matchKeys: string[] = ['ethertype:88b7']
        public readonly matchPriority: number = 10
        public match(): boolean { return !!this.prevCodecModule && this.prevCodecModule.id === 'eth' }
    }
    // LoPri registered first; without priority ordering it would win by registration order.
    const codec: Codec = new Codec([LoPri as any, HiPri as any])
    const decoded: CodecDecodeResult[] = await codec.decode(ethFrame('88b7', '01020304'))
    assert.ok(decoded.some((l: CodecDecodeResult): boolean => l.id === 'hi-pri'), 'higher matchPriority selected')
    assert.ok(decoded.every((l: CodecDecodeResult): boolean => l.id !== 'lo-pri'), 'lower-priority candidate not selected')
})

// M1③a: TCP/UDP now produce a port demux key (from both src and dst port), so a protocol can be
// dispatched by its well-known port in O(1). A codec registered under tcpport:<port> is reached after
// a TCP layer carrying that port.
test('TCP produces a tcpport demux key: a codec keyed on tcpport:9999 is reached after tcp dstport 9999', async (): Promise<void> => {
    class TcpPortChild extends BaseHeader {
        public readonly SCHEMA: ProtocolJSONSchema = {type: 'object', properties: {}}
        public readonly id: string = 'tcpport-child'
        public readonly name: string = 'TCP Port Child'
        public readonly nickname: string = 'TPC'
        public readonly matchKeys: string[] = ['tcpport:9999']
        public match(): boolean { return !!this.prevCodecModule && this.prevCodecModule.id === 'tcp' }
    }
    const codec: Codec = new Codec([TcpPortChild as any])
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '1.2.3.4', dip: '5.6.7.8', protocol: 6}},
        {id: 'tcp', data: {srcport: 1234, dstport: 9999}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(Buffer.concat([packet, Buffer.from('abcd', 'hex')]))
    assert.ok(decoded.some((l: CodecDecodeResult): boolean => l.id === 'tcpport-child'), 'reached via tcpport:9999 bucket')
})

test('UDP produces a udpport demux key, isolated from tcpport (namespace separation)', async (): Promise<void> => {
    class UdpPortChild extends BaseHeader {
        public readonly SCHEMA: ProtocolJSONSchema = {type: 'object', properties: {}}
        public readonly id: string = 'udpport-child'
        public readonly name: string = 'UDP Port Child'
        public readonly nickname: string = 'UPC'
        public readonly matchKeys: string[] = ['udpport:9999']
        public match(): boolean { return !!this.prevCodecModule && this.prevCodecModule.id === 'udp' }
    }
    const codec: Codec = new Codec([UdpPortChild as any])
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '1.2.3.4', dip: '5.6.7.8', protocol: 17}},
        {id: 'udp', data: {srcport: 1234, dstport: 9999}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(Buffer.concat([packet, Buffer.from('abcd', 'hex')]))
    assert.ok(decoded.some((l: CodecDecodeResult): boolean => l.id === 'udpport-child'), 'reached via udpport:9999')
    // A tcpport-keyed codec must NOT be reachable over UDP (namespaces are separate).
    class TcpPortOnly extends BaseHeader {
        public readonly SCHEMA: ProtocolJSONSchema = {type: 'object', properties: {}}
        public readonly id: string = 'tcpport-only'
        public readonly name: string = 'TCP Port Only'
        public readonly nickname: string = 'TPO'
        public readonly matchKeys: string[] = ['tcpport:9999']
        public match(): boolean { return true }
    }
    const codec2: Codec = new Codec([TcpPortOnly as any])
    const {packet: p2}: {packet: Buffer} = await codec2.encode([
        {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '1.2.3.4', dip: '5.6.7.8', protocol: 17}},
        {id: 'udp', data: {srcport: 1234, dstport: 9999}}
    ])
    const decoded2: CodecDecodeResult[] = await codec2.decode(Buffer.concat([p2, Buffer.from('abcd', 'hex')]))
    assert.ok(decoded2.every((l: CodecDecodeResult): boolean => l.id !== 'tcpport-only'), 'tcpport codec not reached over udp (udpport:9999 ≠ tcpport:9999)')
})

// M1③b: TLS/IEC104 are registered in their port buckets (443/2404) for the O(1) fast path, yet stay
// in the heuristic fallback — so TLS on a non-443 port is still recognized by content.
test('TLS on a non-443 port (8443) is still recognized via the heuristic fallback', async (): Promise<void> => {
    const codec: Codec = new Codec()
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('tls/clienthello').buffer)
    // Move it off 443 (fixture is 12345→443) and re-encode faithfully (checksums recomputed).
    ;(decoded.find((l: CodecDecodeResult): boolean => l.id === 'tcp')!.data as any).dstport = 8443
    const {packet}: {packet: Buffer} = await codec.encode(decoded)
    const redecoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(redecoded.some((l: CodecDecodeResult): boolean => l.id === 'tls-handshake'), 'TLS still decoded on tcp:8443')
    // And a content-heuristic child on a non-well-known port is NOT flagged as inconsistent (dual codec).
    assert.deepStrictEqual(codec.checkConsistency(redecoded), [])
})

test('a non-TLS payload on tcp:443 falls to raw, not mis-decoded as TLS', async (): Promise<void> => {
    const codec: Codec = new Codec()
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '1.2.3.4', dip: '5.6.7.8', protocol: 6}},
        {id: 'tcp', data: {srcport: 12345, dstport: 443}}
    ])
    // "GET / HTTP/1.1\r\n" — first byte 0x47 is not a TLS content type (0x14–0x18), so the tcpport:443
    // bucket's TLS candidates all reject it by content and it falls through to raw.
    const withHttp: Buffer = Buffer.concat([packet, Buffer.from('474554202f20485454502f312e310d0a', 'hex')])
    const decoded: CodecDecodeResult[] = await codec.decode(withHttp)
    assert.ok(decoded.every((l: CodecDecodeResult): boolean => !l.id.startsWith('tls')), 'not mis-decoded as TLS')
    assert.ok(decoded.some((l: CodecDecodeResult): boolean => l.id === 'raw'), 'payload lands in raw')
})

// A custom codec WITHOUT a demux key still works via the heuristic fallback list.
test('custom codec without matchKeys is still reachable via heuristic fallback', async (): Promise<void> => {
    class Proto88B5Heuristic extends BaseHeader {
        public readonly SCHEMA: ProtocolJSONSchema = {
            type: 'object',
            properties: {}
        }
        public readonly id: string = 'proto88b5h'
        public readonly name: string = 'Experimental 0x88B5 (heuristic)'
        public readonly nickname: string = 'EXP2'

        public match(): boolean {
            if (!this.prevCodecModule) return false
            return this.prevCodecModule.instance.etherType.getValue() === '88b5'
        }
    }

    const codec: Codec = new Codec([Proto88B5Heuristic as any])
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('codec/unknown-ethertype').buffer)
    Layer(decoded, 'proto88b5h')
})

// KNOWN BUG: encode silently skips inputs whose id matches no registered codec -
// the layer is missing from the output packet and no error is recorded.
test('encode with unknown protocol id must record an error', async (): Promise<void> => {
    const codec: Codec = new Codec()
    const result = await codec.encode([{id: 'no-such-protocol', data: {}} as any])
    assert.ok(result.errors.length > 0, 'silently dropping a layer is not acceptable')
})

// KNOWN BUG: encoding a deliberately malformed stack (e.g. TCP with no IP layer
// beneath it) throws inside the checksum post-handler, which assumes a previous
// layer exists (this.prevCodecModule.instance.version). Building error packets
// on purpose is a legitimate use case; it must accumulate errors, not throw.
test('encode a malformed stack (TCP with no IP below) must not throw', async (): Promise<void> => {
    const codec: Codec = new Codec()
    await assert.doesNotReject(async (): Promise<void> => {
        void await codec.encode([{id: 'tcp', data: {srcport: 80, dstport: 443}} as any])
    })
})
