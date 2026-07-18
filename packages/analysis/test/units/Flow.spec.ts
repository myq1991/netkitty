import {test} from 'node:test'
import assert from 'node:assert'
import {Codec, CodecDecodeResult} from '@netkitty/codec'
import {LoadPacket} from '../lib/Fixtures'
import {AnalysisPacket, Conversation, Endpoint, FlowAnalysis, FlowAnalyzer} from '../../src'

const codec: Codec = new Codec()
const analyzer: FlowAnalyzer = new FlowAnalyzer()

// A minimal decoded layer, enough to exercise the analyzer (it reads only id + a few data fields).
function layer(id: string, data: Record<string, unknown>): CodecDecodeResult {
    return {id: id, name: id, nickname: id, protocol: true, errors: [], data: data as any}
}

function tcpPacket(sip: string, sport: number, dip: string, dport: number, timestamp: number, length: number): AnalysisPacket {
    return {layers: [layer('eth', {}), layer('ipv4', {sip: sip, dip: dip}), layer('tcp', {srcport: sport, dstport: dport})], timestamp: timestamp, length: length}
}

test('flow: A→B and B→A collapse into one bidirectional conversation', (): void => {
    const packets: AnalysisPacket[] = [
        tcpPacket('10.0.0.1', 1234, '10.0.0.2', 80, 1.0, 100),
        tcpPacket('10.0.0.2', 80, '10.0.0.1', 1234, 1.5, 200),
        tcpPacket('10.0.0.1', 1234, '10.0.0.2', 80, 2.0, 150)
    ]
    const result: FlowAnalysis = analyzer.analyze(packets)
    assert.strictEqual(result.conversations.length, 1)
    const conversation: Conversation = result.conversations[0]
    assert.strictEqual(conversation.protocol, 'tcp')
    assert.strictEqual(conversation.packets, 3)
    assert.strictEqual(conversation.bytes, 450)
    // Canonical A = smaller endpoint string "10.0.0.1:1234"; two packets from A, one from B.
    assert.strictEqual(conversation.endpointA, '10.0.0.1:1234')
    assert.strictEqual(conversation.endpointB, '10.0.0.2:80')
    assert.strictEqual(conversation.packetsAToB, 2)
    assert.strictEqual(conversation.packetsBToA, 1)
    assert.strictEqual(conversation.firstTimestamp, 1.0)
    assert.strictEqual(conversation.lastTimestamp, 2.0)
    assert.deepStrictEqual(conversation.packetIndices, [0, 1, 2])
})

test('flow: distinct 5-tuples form separate conversations', (): void => {
    const packets: AnalysisPacket[] = [
        tcpPacket('10.0.0.1', 1234, '10.0.0.2', 80, 1.0, 100),
        tcpPacket('10.0.0.1', 5555, '10.0.0.3', 443, 1.0, 100)
    ]
    assert.strictEqual(analyzer.analyze(packets).conversations.length, 2)
})

test('flow: per-endpoint tx/rx totals are direction-aware', (): void => {
    const packets: AnalysisPacket[] = [
        tcpPacket('10.0.0.1', 1234, '10.0.0.2', 80, 1.0, 100),
        tcpPacket('10.0.0.2', 80, '10.0.0.1', 1234, 1.5, 200)
    ]
    const endpoints: Endpoint[] = analyzer.analyze(packets).endpoints
    const a: Endpoint = endpoints.find((e: Endpoint): boolean => e.address === '10.0.0.1:1234') as Endpoint
    assert.strictEqual(a.packets, 2)
    assert.strictEqual(a.txPackets, 1)
    assert.strictEqual(a.txBytes, 100)
    assert.strictEqual(a.rxPackets, 1)
    assert.strictEqual(a.rxBytes, 200)
})

test('flow: consumes real decode output (udp/netbios)', async (): Promise<void> => {
    const layers: CodecDecodeResult[] = await codec.decode(LoadPacket('udp/netbios').buffer)
    const result: FlowAnalysis = analyzer.analyze([{layers: layers, timestamp: 0, length: 100}])
    assert.strictEqual(result.conversations.length, 1)
    assert.strictEqual(result.conversations[0].protocol, 'udp')
    assert.ok(result.conversations[0].endpointA.includes('192.168.1.'))
})

test('flow: non-IP packet falls back to an Ethernet MAC conversation (arp)', async (): Promise<void> => {
    const layers: CodecDecodeResult[] = await codec.decode(LoadPacket('arp/baseline').buffer)
    const result: FlowAnalysis = analyzer.analyze([{layers: layers, timestamp: 0, length: 60}])
    assert.strictEqual(result.conversations.length, 1)
    assert.strictEqual(result.conversations[0].protocol, 'eth')
})
