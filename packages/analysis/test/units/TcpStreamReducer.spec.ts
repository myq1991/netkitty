import {test} from 'node:test'
import assert from 'node:assert'
import {CodecDecodeResult} from '@netkitty/codec'
import {Frame} from '../../src/lib/streaming/types/Frame'
import {UpdateContext} from '../../src/lib/streaming/types/UpdateContext'
import {RttSample, TcpStreamDiagnostic, TcpStreamReducer} from '../../src/lib/streaming/reducers/TcpStreamReducer'

type Packet = {layers: CodecDecodeResult[], timestamp: number, length: number}

const CTX: UpdateContext = {index: 0, total: 0, phase: 'replay'}

function layer(id: string, data: Record<string, unknown>): CodecDecodeResult {
    return {id: id, name: id, nickname: id, protocol: true, errors: [], data: data as any}
}

function seg(sip: string, sport: number, dip: string, dport: number, seq: number, ack: number, flags: {syn?: boolean, fin?: boolean, ack?: boolean, push?: boolean}, payload: number, timestamp: number): Packet {
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

function scenario(): Packet[] {
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

function frameOf(packet: Packet, index: number): Frame {
    return {index: index, timestamp: packet.timestamp, length: packet.length, capturedLength: packet.length, topProtocol: 'tcp', conversationKey: null, info: '', layers: packet.layers}
}

function reduceStreams(packets: Packet[]): TcpStreamDiagnostic[] {
    const reducer: TcpStreamReducer = new TcpStreamReducer()
    packets.forEach((packet: Packet, index: number): void => reducer.update(frameOf(packet, index), CTX))
    return reducer.result()
}

const r3 = (n: number): number => Math.round(n * 1000) / 1000

test('tcp reducer: derives retransmission/dupACK/RTT for a full handshake+data scenario', (): void => {
    const streamed: TcpStreamDiagnostic[] = reduceStreams(scenario())
    assert.strictEqual(streamed.length, 1)
    const got: TcpStreamDiagnostic = streamed[0]
    assert.strictEqual(got.key, 'tcp|10.0.0.1:1234|10.0.0.2:80')
    assert.strictEqual(got.packets, 7)
    assert.deepStrictEqual(got.retransmissions, [4])
    assert.deepStrictEqual(got.duplicateAcks, [6])
    //Three RTT samples: SYN→SYN,ACK; client ACK covering the SYN,ACK; server ACK covering the 100B data.
    const samples: number[][] = got.rttSamples.map((s: RttSample): number[] => [s.segmentIndex, s.ackIndex, r3(s.rtt)])
    assert.deepStrictEqual(samples, [[0, 1, 0.1], [1, 2, 0.05], [3, 5, 0.4]])
    assert.strictEqual(r3(got.rttMin as number), 0.05)
    assert.strictEqual(r3(got.rttMax as number), 0.4)
    assert.strictEqual(r3(got.rttMean as number), 0.183)
})

test('tcp reducer: flags retransmission #4 and duplicate ACK #6', (): void => {
    const stream: TcpStreamDiagnostic = reduceStreams(scenario())[0]
    assert.deepStrictEqual(stream.retransmissions, [4])
    assert.deepStrictEqual(stream.duplicateAcks, [6])
    assert.strictEqual(stream.rttSamples.length, 3)
})

test('tcp reducer: result() is a rolling snapshot with recomputed RTT summary', (): void => {
    const reducer: TcpStreamReducer = new TcpStreamReducer()
    const packets: Packet[] = scenario()
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
