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
