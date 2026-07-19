import {test} from 'node:test'
import assert from 'node:assert'
import {CodecDecodeResult} from '@netkitty/codec'
import {Frame} from '../../src/lib/streaming/types/Frame'
import {UpdateContext} from '../../src/lib/streaming/types/UpdateContext'
import {ConversationSummary, ConversationsReducer} from '../../src/lib/streaming/reducers/ConversationsReducer'
import {EndpointSummary, EndpointsReducer} from '../../src/lib/streaming/reducers/EndpointsReducer'

type Packet = {layers: CodecDecodeResult[], timestamp: number, length: number}

function layer(id: string, data: Record<string, unknown>): CodecDecodeResult {
    return {id: id, name: id, nickname: id, protocol: true, errors: [], data: data as any}
}

function tcpPacket(sip: string, sport: number, dip: string, dport: number, timestamp: number, length: number): Packet {
    return {layers: [layer('eth', {}), layer('ipv4', {sip: sip, dip: dip}), layer('tcp', {srcport: sport, dstport: dport})], timestamp: timestamp, length: length}
}

function frameOf(packet: Packet, index: number): Frame {
    return {index: index, timestamp: packet.timestamp, length: packet.length, capturedLength: packet.length, topProtocol: 'tcp', conversationKey: null, info: '', layers: packet.layers}
}

const CTX: UpdateContext = {index: 0, total: 0, phase: 'replay'}

const PACKETS: Packet[] = [
    tcpPacket('10.0.0.1', 1234, '10.0.0.2', 80, 1.0, 100),
    tcpPacket('10.0.0.2', 80, '10.0.0.1', 1234, 1.5, 200),
    tcpPacket('10.0.0.1', 1234, '10.0.0.2', 80, 2.0, 150),
    tcpPacket('10.0.0.3', 5000, '10.0.0.4', 443, 3.0, 300)
]

test('builtin reducers: ConversationsReducer groups directionally by n-tuple', (): void => {
    const reducer: ConversationsReducer = new ConversationsReducer()
    PACKETS.forEach((packet: Packet, index: number): void => reducer.update(frameOf(packet, index), CTX))
    const streamed: ConversationSummary[] = reducer.result()

    const expected: ConversationSummary[] = [
        {protocol: 'tcp', endpointA: '10.0.0.1:1234', endpointB: '10.0.0.2:80', packets: 3, bytes: 450, packetsAToB: 2, packetsBToA: 1, firstTimestamp: 1.0, lastTimestamp: 2.0, firstIndex: 0, lastIndex: 2},
        {protocol: 'tcp', endpointA: '10.0.0.3:5000', endpointB: '10.0.0.4:443', packets: 1, bytes: 300, packetsAToB: 1, packetsBToA: 0, firstTimestamp: 3.0, lastTimestamp: 3.0, firstIndex: 3, lastIndex: 3}
    ]
    assert.strictEqual(streamed.length, expected.length)
    for (const want of expected) {
        const got: ConversationSummary | undefined = streamed.find((c: ConversationSummary): boolean => c.endpointA === want.endpointA && c.endpointB === want.endpointB && c.protocol === want.protocol)
        assert.ok(got, `conversation ${want.endpointA}↔${want.endpointB} present`)
        assert.deepStrictEqual(got, want)
    }
})

test('builtin reducers: EndpointsReducer credits source (tx) and destination (rx)', (): void => {
    const reducer: EndpointsReducer = new EndpointsReducer()
    PACKETS.forEach((packet: Packet, index: number): void => reducer.update(frameOf(packet, index), CTX))
    const streamed: EndpointSummary[] = reducer.result()

    const expected: EndpointSummary[] = [
        {address: '10.0.0.1:1234', packets: 3, bytes: 450, txPackets: 2, txBytes: 250, rxPackets: 1, rxBytes: 200},
        {address: '10.0.0.2:80', packets: 3, bytes: 450, txPackets: 1, txBytes: 200, rxPackets: 2, rxBytes: 250},
        {address: '10.0.0.3:5000', packets: 1, bytes: 300, txPackets: 1, txBytes: 300, rxPackets: 0, rxBytes: 0},
        {address: '10.0.0.4:443', packets: 1, bytes: 300, txPackets: 0, txBytes: 0, rxPackets: 1, rxBytes: 300}
    ]
    assert.strictEqual(streamed.length, expected.length)
    for (const want of expected) {
        const got: EndpointSummary | undefined = streamed.find((e: EndpointSummary): boolean => e.address === want.address)
        assert.ok(got, `endpoint ${want.address} present`)
        assert.deepStrictEqual(got, want)
    }
})

test('builtin reducers: result() is a rolling snapshot and reset() clears state', (): void => {
    const reducer: ConversationsReducer = new ConversationsReducer()
    reducer.update(frameOf(PACKETS[0], 0), CTX)
    assert.strictEqual(reducer.result().length, 1)
    assert.strictEqual(reducer.result()[0].packets, 1)
    reducer.update(frameOf(PACKETS[1], 1), CTX)
    assert.strictEqual(reducer.result()[0].packets, 2, 'snapshot reflects new frames')
    reducer.reset()
    assert.strictEqual(reducer.result().length, 0)
})

test('builtin reducers: frames with no derivable flow are ignored', (): void => {
    const reducer: ConversationsReducer = new ConversationsReducer()
    const raw: Frame = {index: 0, timestamp: 0, length: 10, capturedLength: 10, topProtocol: 'raw', conversationKey: null, info: '', layers: [{id: 'raw', name: 'raw', nickname: 'raw', protocol: false, errors: [], data: {} as any}]}
    reducer.update(raw, CTX)
    assert.strictEqual(reducer.result().length, 0)
})
