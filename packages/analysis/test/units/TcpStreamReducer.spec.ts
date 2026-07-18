import {test} from 'node:test'
import assert from 'node:assert'
import {CodecDecodeResult} from '@netkitty/codec'
import {AnalysisPacket, RttSample, TcpAnalysis, TcpStreamAnalyzer, TcpStreamDiagnostic} from '../../src'
import {Frame} from '../../src/lib/streaming/types/Frame'
import {UpdateContext} from '../../src/lib/streaming/types/UpdateContext'
import {TcpStreamReducer} from '../../src/lib/streaming/reducers/TcpStreamReducer'

const CTX: UpdateContext = {index: 0, total: 0, phase: 'replay'}

function layer(id: string, data: Record<string, unknown>): CodecDecodeResult {
    return {id: id, name: id, nickname: id, protocol: true, errors: [], data: data as any}
}

function seg(sip: string, sport: number, dip: string, dport: number, seq: number, ack: number, flags: {syn?: boolean, fin?: boolean, ack?: boolean, push?: boolean}, payload: number, timestamp: number): AnalysisPacket {
    return {
        layers: [
            layer('eth', {}),
            layer('ipv4', {sip: sip, dip: dip, hdrLen: 20, length: 40 + payload}),
            layer('tcp', {srcport: sport, dstport: dport, seq: seq, ack: ack, hdrLen: 20, flags: {syn: !!flags.syn, fin: !!flags.fin, ack: !!flags.ack, push: !!flags.push}})
        ],
        timestamp: timestamp,
        length: 54 + payload
    }
}

function scenario(): AnalysisPacket[] {
    const C: [string, number] = ['10.0.0.1', 1234]
    const S: [string, number] = ['10.0.0.2', 80]
    return [
        seg(C[0], C[1], S[0], S[1], 0, 0, {syn: true}, 0, 0.0),
        seg(S[0], S[1], C[0], C[1], 0, 1, {syn: true, ack: true}, 0, 0.1),
        seg(C[0], C[1], S[0], S[1], 1, 1, {ack: true}, 0, 0.15),
        seg(C[0], C[1], S[0], S[1], 1, 1, {ack: true, push: true}, 100, 0.2),
        seg(C[0], C[1], S[0], S[1], 1, 1, {ack: true, push: true}, 100, 0.5),
        seg(S[0], S[1], C[0], C[1], 1, 101, {ack: true}, 0, 0.6),
        seg(S[0], S[1], C[0], C[1], 1, 101, {ack: true}, 0, 0.7)
    ]
}

function frameOf(packet: AnalysisPacket, index: number): Frame {
    return {index: index, timestamp: packet.timestamp, length: packet.length, capturedLength: packet.length, topProtocol: 'tcp', conversationKey: null, info: '', layers: packet.layers}
}

function reduceStreams(packets: AnalysisPacket[]): TcpStreamDiagnostic[] {
    const reducer: TcpStreamReducer = new TcpStreamReducer()
    packets.forEach((packet: AnalysisPacket, index: number): void => reducer.update(frameOf(packet, index), CTX))
    return reducer.result()
}

test('tcp reducer: matches TcpStreamAnalyzer on retransmission/dupACK/RTT', (): void => {
    const legacy: TcpAnalysis = new TcpStreamAnalyzer().analyze(scenario())
    const streamed: TcpStreamDiagnostic[] = reduceStreams(scenario())
    assert.strictEqual(streamed.length, legacy.streams.length)
    const expected: TcpStreamDiagnostic = legacy.streams[0]
    const got: TcpStreamDiagnostic = streamed[0]
    assert.strictEqual(got.key, expected.key)
    assert.strictEqual(got.packets, expected.packets)
    assert.deepStrictEqual(got.retransmissions, expected.retransmissions)
    assert.deepStrictEqual(got.duplicateAcks, expected.duplicateAcks)
    const rttOf = (s: TcpStreamDiagnostic): number[] => s.rttSamples.map((r: RttSample): number => Math.round(r.rtt * 1000) / 1000).sort((a: number, b: number): number => a - b)
    assert.deepStrictEqual(rttOf(got), rttOf(expected))
    assert.strictEqual(got.rttMin, expected.rttMin)
    assert.strictEqual(got.rttMax, expected.rttMax)
    assert.strictEqual(got.rttMean, expected.rttMean)
})

test('tcp reducer: flags retransmission #4 and duplicate ACK #6', (): void => {
    const stream: TcpStreamDiagnostic = reduceStreams(scenario())[0]
    assert.deepStrictEqual(stream.retransmissions, [4])
    assert.deepStrictEqual(stream.duplicateAcks, [6])
    assert.strictEqual(stream.rttSamples.length, 3)
})

test('tcp reducer: result() is a rolling snapshot with recomputed RTT summary', (): void => {
    const reducer: TcpStreamReducer = new TcpStreamReducer()
    const packets: AnalysisPacket[] = scenario()
    reducer.update(frameOf(packets[0], 0), CTX)
    reducer.update(frameOf(packets[1], 1), CTX)
    const early: TcpStreamDiagnostic = reducer.result()[0]
    assert.strictEqual(early.rttSamples.length, 1, 'SYN→SYN,ACK sample so far')
    assert.strictEqual(early.rttMean, early.rttSamples[0].rtt)
    for (let i: number = 2; i < packets.length; i++) reducer.update(frameOf(packets[i], i), CTX)
    assert.strictEqual(reducer.result()[0].rttSamples.length, 3, 'snapshot reflects later frames')
})

test('tcp reducer: non-TCP frames are ignored', (): void => {
    const reducer: TcpStreamReducer = new TcpStreamReducer()
    const arp: Frame = {index: 0, timestamp: 0, length: 60, capturedLength: 60, topProtocol: 'arp', conversationKey: null, info: '', layers: [layer('eth', {}), layer('arp', {})]}
    reducer.update(arp, CTX)
    assert.strictEqual(reducer.result().length, 0)
})
