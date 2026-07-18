import {test} from 'node:test'
import assert from 'node:assert'
import {CodecDecodeResult} from '../../lib/codec/types/CodecDecodeResult'
import {AnalysisPacket} from '../../lib/analysis/FlowAnalyzer'
import {RttSample, TcpAnalysis, TcpStreamAnalyzer, TcpStreamDiagnostic} from '../../lib/analysis/TcpStreamAnalyzer'

const analyzer: TcpStreamAnalyzer = new TcpStreamAnalyzer()

function layer(id: string, data: Record<string, unknown>): CodecDecodeResult {
    return {id: id, name: id, nickname: id, protocol: true, errors: [], data: data as any}
}

type Flags = {syn?: boolean, fin?: boolean, ack?: boolean, push?: boolean}

// Build a TCP-over-IPv4 packet. ipv4.length encodes the payload: 20 (IP) + 20 (TCP) + payload.
function seg(sip: string, sport: number, dip: string, dport: number, seq: number, ack: number, flags: Flags, payload: number, timestamp: number): AnalysisPacket {
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

// Client 10.0.0.1:1234 ↔ Server 10.0.0.2:80: handshake, one data segment, its retransmission,
// the server ACK, and a duplicate ACK.
function scenario(): AnalysisPacket[] {
    const C: [string, number] = ['10.0.0.1', 1234]
    const S: [string, number] = ['10.0.0.2', 80]
    return [
        seg(C[0], C[1], S[0], S[1], 0, 0, {syn: true}, 0, 0.0),                 // 0 SYN
        seg(S[0], S[1], C[0], C[1], 0, 1, {syn: true, ack: true}, 0, 0.1),      // 1 SYN,ACK (covers SYN → rtt 0.1)
        seg(C[0], C[1], S[0], S[1], 1, 1, {ack: true}, 0, 0.15),                // 2 ACK (covers SYN,ACK → rtt 0.05)
        seg(C[0], C[1], S[0], S[1], 1, 1, {ack: true, push: true}, 100, 0.2),   // 3 data 100B
        seg(C[0], C[1], S[0], S[1], 1, 1, {ack: true, push: true}, 100, 0.5),   // 4 RETRANSMISSION
        seg(S[0], S[1], C[0], C[1], 1, 101, {ack: true}, 0, 0.6),               // 5 ACK data (covers #3 → rtt 0.4)
        seg(S[0], S[1], C[0], C[1], 1, 101, {ack: true}, 0, 0.7)               // 6 DUP ACK (same ack 101)
    ]
}

test('tcp: retransmission is flagged (segment #4 replays #3)', (): void => {
    const result: TcpAnalysis = analyzer.analyze(scenario())
    assert.strictEqual(result.streams.length, 1)
    assert.deepStrictEqual(result.streams[0].retransmissions, [4])
})

test('tcp: duplicate ACK is flagged (server repeats ack=101)', (): void => {
    const stream: TcpStreamDiagnostic = analyzer.analyze(scenario()).streams[0]
    assert.deepStrictEqual(stream.duplicateAcks, [6])
})

test('tcp: RTT samples pair segments with the ACK that covers them', (): void => {
    const stream: TcpStreamDiagnostic = analyzer.analyze(scenario()).streams[0]
    // SYN→SYN,ACK (0.1), SYN,ACK→ACK (0.05), data→server ACK (0.4). Retransmit #4 is not an RTT source.
    const rtts: number[] = stream.rttSamples.map((s: RttSample): number => Math.round(s.rtt * 1000) / 1000)
    assert.deepStrictEqual(rtts.sort((a: number, b: number): number => a - b), [0.05, 0.1, 0.4])
    assert.ok(stream.rttMin !== null && stream.rttMin > 0 && stream.rttMax !== null && stream.rttMax < 1)
})

test('tcp: a clean stream reports no retransmissions or duplicate ACKs', (): void => {
    const clean: AnalysisPacket[] = scenario().filter((_p: AnalysisPacket, i: number): boolean => i !== 4 && i !== 6)
    const stream: TcpStreamDiagnostic = analyzer.analyze(clean).streams[0]
    assert.deepStrictEqual(stream.retransmissions, [])
    assert.deepStrictEqual(stream.duplicateAcks, [])
})

test('tcp: non-TCP packets are ignored', (): void => {
    const arp: AnalysisPacket = {layers: [layer('eth', {}), layer('arp', {})], timestamp: 0, length: 60}
    assert.strictEqual(analyzer.analyze([arp]).streams.length, 0)
})

// IPv6 TCP: payload must derive from the IPv6 `plen` field (not `length`, which IPv6 has no such field
// for). Regression for the bug where IPv6 payload came out NaN→0, making data segments look like pure
// ACKs so retransmissions/RTT were never detected.
function seg6(sip: string, sport: number, dip: string, dport: number, seq: number, ack: number, flags: Flags, payload: number, timestamp: number): AnalysisPacket {
    return {
        layers: [
            layer('eth', {}),
            layer('ipv6', {sip: sip, dip: dip, plen: 20 + payload}),
            layer('tcp', {srcport: sport, dstport: dport, seq: seq, ack: ack, hdrLen: 20, flags: {syn: !!flags.syn, fin: !!flags.fin, ack: !!flags.ack, push: !!flags.push}})
        ],
        timestamp: timestamp,
        length: 74 + payload
    }
}

test('tcp: IPv6 payload derives from plen (retransmission detected over IPv6)', (): void => {
    const packets: AnalysisPacket[] = [
        seg6('2001::1', 1234, '2001::2', 80, 1, 1, {ack: true, push: true}, 100, 0.1),
        seg6('2001::1', 1234, '2001::2', 80, 1, 1, {ack: true, push: true}, 100, 0.3), // retransmission
        seg6('2001::2', 80, '2001::1', 1234, 1, 101, {ack: true}, 0, 0.4)              // ACK covering the data
    ]
    const stream: TcpStreamDiagnostic = analyzer.analyze(packets).streams[0]
    assert.deepStrictEqual(stream.retransmissions, [1], 'IPv6 data segment #1 replays #0')
    assert.strictEqual(stream.rttSamples.length, 1, 'the IPv6 data segment is RTT-matched by its ACK')
})

test('tcp: sequence wraparound past 2^32 is not misread as retransmission', (): void => {
    // First segment ends near the 32-bit ceiling; the next segment's seq has wrapped to a small value.
    // A naive seq<=maxEndSeq comparison would flag the wrapped (genuinely new) segment as a retransmit.
    const packets: AnalysisPacket[] = [
        seg('10.0.0.1', 1234, '10.0.0.2', 80, 4294967200, 1, {ack: true, push: true}, 100, 0.1),
        seg('10.0.0.1', 1234, '10.0.0.2', 80, 4, 1, {ack: true, push: true}, 100, 0.2)
    ]
    assert.deepStrictEqual(analyzer.analyze(packets).streams[0].retransmissions, [])
})
