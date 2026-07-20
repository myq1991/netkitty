import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// BFD Control (RFC 5880) on UDP 3784, session state Up, no auth — the 24-byte mandatory section.
test('BFD Control (state Up): mandatory section decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('bfd/control-up').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'bfd'])
    const bfd: any = Layer(decoded, 'bfd').data
    assert.strictEqual(bfd.version, 1, 'BFD version 1')
    assert.strictEqual(bfd.flags.state, 3, 'session state Up')
    assert.strictEqual(bfd.flags.authPresent, false)
    assert.strictEqual(bfd.detectMult, 3)
    assert.strictEqual(bfd.length, 24)
    assert.strictEqual(bfd.myDiscriminator, 1)
    assert.strictEqual(bfd.yourDiscriminator, 2)
    assert.strictEqual(bfd.desiredMinTxInterval, 1000000)
    assert.strictEqual(bfd.authSection, '', 'no auth section')
})

// With the A (Authentication Present) flag set, the trailing auth section is kept verbatim.
test('BFD Control with Authentication Present: auth section preserved verbatim + byte-perfect', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('bfd/control-auth').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'bfd'])
    const bfd: any = Layer(decoded, 'bfd').data
    assert.strictEqual(bfd.flags.authPresent, true, 'A flag set')
    assert.strictEqual(bfd.length, 30)
    assert.strictEqual(bfd.authSection, '010601616263', 'Simple Password auth section (type 1, len 6, key 1, "abc")')
})

// Crafting: build a Poll/Final BFD packet with a Down state and non-default discriminators — the codec
// faithfully re-emits it (Length honored verbatim, not recomputed).
test('BFD faithfully encodes a crafted Poll packet (Down state)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 49152, dstport: 3784}},
        {id: 'bfd', data: {
            version: 1, diagnostic: 1,
            flags: {state: 1, poll: true, final: false, controlPlaneIndependent: false, authPresent: false, demand: false, multipoint: false},
            detectMult: 5, length: 24, myDiscriminator: 0x11223344, yourDiscriminator: 0, desiredMinTxInterval: 250000, requiredMinRxInterval: 250000, requiredMinEchoRxInterval: 0
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'bfd'])
    const bfd: any = Layer(decoded, 'bfd').data
    assert.strictEqual(bfd.flags.state, 1, 'Down')
    assert.strictEqual(bfd.flags.poll, true, 'Poll bit set')
    assert.strictEqual(bfd.diagnostic, 1)
    assert.strictEqual(bfd.myDiscriminator, 0x11223344)
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A UDP/3784 datagram too short to hold the 24-byte mandatory section must fall through to raw.
test('BFD too-short UDP/3784 payload falls through to RawData', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 49152, dstport: 3784}},
        {id: 'raw', data: {data: '20c003180000000100000002'}} // only 12 bytes on port 3784
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'bfd'), 'must not claim a 12-byte payload as BFD')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw', 'the short payload stays raw')
})

test('BFD truncated mid-section: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('bfd/control-up').buffer
    await AssertDecodeSurvives(full.subarray(0, 50))
})
