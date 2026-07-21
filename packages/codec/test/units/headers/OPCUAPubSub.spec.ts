import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// The UADP body after the UADPFlags octet (PublisherId, GroupHeader, PayloadHeader, one DataSetMessage).
const BODY: string = '2a0901000100010100010100062a000000'

// OPC UA PubSub (udp:4840) UADP NetworkMessage — UADPFlags octet decomposed into version + 4 enable
// bits, the flag-conditional remainder kept verbatim as body; byte-perfect round-trip.
test('OPCUAPubSub UADP: flags decomposition + verbatim body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('opcua-pubsub/uadp-networkmessage').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'opcua-pubsub'])
    const uadp: any = Layer(decoded, 'opcua-pubsub').data
    assert.strictEqual(uadp.version, 1, 'UADPVersion (low nibble of 0x71)')
    assert.strictEqual(uadp.publisherIdEnabled, 1, 'PublisherId flag (0x10)')
    assert.strictEqual(uadp.groupHeaderEnabled, 1, 'GroupHeader flag (0x20)')
    assert.strictEqual(uadp.payloadHeaderEnabled, 1, 'PayloadHeader flag (0x40)')
    assert.strictEqual(uadp.extendedFlags1Enabled, 0, 'ExtendedFlags1 flag (0x80) off')
    assert.strictEqual(uadp.body, BODY, 'flag-conditional remainder kept verbatim')
})

// Crafting: the minimal UADP NetworkMessage — a bare UADPFlags octet (version 1, no enable bits, empty
// body). The flags reassemble to 0x01 and the message must re-encode byte-identically.
test('OPCUAPubSub faithfully encodes a bare-UADPFlags message and reassembles the octet', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:64', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '239.0.0.100', protocol: 17, ttl: 1}},
        {id: 'udp', data: {srcport: 49320, dstport: 4840}},
        {id: 'opcua-pubsub', data: {version: 1}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'opcua-pubsub'])
    const uadp: any = Layer(decoded, 'opcua-pubsub').data
    assert.strictEqual(uadp.version, 1, 'version 1')
    assert.strictEqual(uadp.publisherIdEnabled, 0, 'no enable bits')
    assert.strictEqual(uadp.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Every one of the 8 UADPFlags bits must round-trip: a crafted message with all enable bits set and a
// non-default version must reproduce the exact UADPFlags octet (0xf5 = version 5 + all four enable bits).
test('OPCUAPubSub reproduces the full UADPFlags octet across all bit positions', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:64', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '239.0.0.100', protocol: 17, ttl: 1}},
        {id: 'udp', data: {srcport: 49320, dstport: 4840}},
        {id: 'opcua-pubsub', data: {version: 5, publisherIdEnabled: 1, groupHeaderEnabled: 1, payloadHeaderEnabled: 1, extendedFlags1Enabled: 1, body: 'dead'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const uadp: any = Layer(decoded, 'opcua-pubsub').data
    assert.strictEqual(uadp.version, 5, 'version nibble honored')
    assert.strictEqual(uadp.extendedFlags1Enabled, 1, 'ExtendedFlags1 bit honored')
    assert.strictEqual(uadp.body, 'dead', 'body verbatim')
    // UADPFlags octet is the first byte after the 42-byte eth+ipv4+udp envelope.
    assert.strictEqual(packet[42], 0xf5, 'UADPFlags octet = 0xf5 (version 5 + all enable bits)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a truncated UADP message must survive decode without throwing; and a non-UADP UDP/4840
// payload (no signature) is still claimed by port but must re-encode without throwing (never-throws).
test('OPCUAPubSub survives truncation and non-UADP payload on udp:4840', async (): Promise<void> => {
    const full: Buffer = LoadPacket('opcua-pubsub/uadp-networkmessage').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))

    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:64', smac: '00:11:22:33:44:55', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '239.0.0.100', protocol: 17, ttl: 1}},
        {id: 'udp', data: {srcport: 49320, dstport: 4840}},
        {id: 'raw', data: {data: '2b3c4d5e6f'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'opcua-pubsub'])
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
