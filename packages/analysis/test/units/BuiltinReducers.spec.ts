import {test} from 'node:test'
import assert from 'node:assert'
import {CodecDecodeResult} from '@netkitty/codec'
import {AnalysisPacket, Endpoint, FlowAnalysis, FlowAnalyzer} from '../../src'
import {Frame} from '../../src/lib/streaming/types/Frame'
import {UpdateContext} from '../../src/lib/streaming/types/UpdateContext'
import {ConversationSummary, ConversationsReducer} from '../../src/lib/streaming/reducers/ConversationsReducer'
import {EndpointSummary, EndpointsReducer} from '../../src/lib/streaming/reducers/EndpointsReducer'

function layer(id: string, data: Record<string, unknown>): CodecDecodeResult {
    return {id: id, name: id, nickname: id, protocol: true, errors: [], data: data as any}
}

function tcpPacket(sip: string, sport: number, dip: string, dport: number, timestamp: number, length: number): AnalysisPacket {
    return {layers: [layer('eth', {}), layer('ipv4', {sip: sip, dip: dip}), layer('tcp', {srcport: sport, dstport: dport})], timestamp: timestamp, length: length}
}

function frameOf(packet: AnalysisPacket, index: number): Frame {
    return {index: index, timestamp: packet.timestamp, length: packet.length, capturedLength: packet.length, topProtocol: 'tcp', conversationKey: null, info: '', layers: packet.layers}
}

const CTX: UpdateContext = {index: 0, total: 0, phase: 'replay'}

const PACKETS: AnalysisPacket[] = [
    tcpPacket('10.0.0.1', 1234, '10.0.0.2', 80, 1.0, 100),
    tcpPacket('10.0.0.2', 80, '10.0.0.1', 1234, 1.5, 200),
    tcpPacket('10.0.0.1', 1234, '10.0.0.2', 80, 2.0, 150),
    tcpPacket('10.0.0.3', 5000, '10.0.0.4', 443, 3.0, 300)
]

test('builtin reducers: ConversationsReducer matches FlowAnalyzer (minus packetIndices)', (): void => {
    const legacy: FlowAnalysis = new FlowAnalyzer().analyze(PACKETS)
    const reducer: ConversationsReducer = new ConversationsReducer()
    PACKETS.forEach((packet: AnalysisPacket, index: number): void => reducer.update(frameOf(packet, index), CTX))
    const streamed: ConversationSummary[] = reducer.result()
    assert.strictEqual(streamed.length, legacy.conversations.length)
    for (const expected of legacy.conversations) {
        const got: ConversationSummary | undefined = streamed.find((c: ConversationSummary): boolean => c.endpointA === expected.endpointA && c.endpointB === expected.endpointB && c.protocol === expected.protocol)
        assert.ok(got, `conversation ${expected.endpointA}↔${expected.endpointB} present`)
        assert.strictEqual(got!.packets, expected.packets)
        assert.strictEqual(got!.bytes, expected.bytes)
        assert.strictEqual(got!.packetsAToB, expected.packetsAToB)
        assert.strictEqual(got!.packetsBToA, expected.packetsBToA)
        assert.strictEqual(got!.firstTimestamp, expected.firstTimestamp)
        assert.strictEqual(got!.lastTimestamp, expected.lastTimestamp)
        //firstIndex/lastIndex replace packetIndices: they are the span of the member index list.
        assert.strictEqual(got!.firstIndex, expected.packetIndices[0])
        assert.strictEqual(got!.lastIndex, expected.packetIndices[expected.packetIndices.length - 1])
    }
})

test('builtin reducers: EndpointsReducer matches FlowAnalyzer endpoints', (): void => {
    const legacy: FlowAnalysis = new FlowAnalyzer().analyze(PACKETS)
    const reducer: EndpointsReducer = new EndpointsReducer()
    PACKETS.forEach((packet: AnalysisPacket, index: number): void => reducer.update(frameOf(packet, index), CTX))
    const streamed: EndpointSummary[] = reducer.result()
    assert.strictEqual(streamed.length, legacy.endpoints.length)
    for (const expected of legacy.endpoints) {
        const got: EndpointSummary | undefined = streamed.find((e: EndpointSummary): boolean => e.address === expected.address)
        assert.ok(got, `endpoint ${expected.address} present`)
        assert.deepStrictEqual(got, expected as Endpoint)
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
