import {CodecDecodeResult} from '../codec/types/CodecDecodeResult'
import {AnalysisPacket} from './FlowAnalyzer'

/**
 * TCP stream deep analysis — an optional read-only analyzer layered above FlowAnalyzer. It consumes
 * the same AnalysisPacket list, groups TCP packets by directional flow, and derives per-stream
 * diagnostics from each segment's seq/ack/flags/payload-length/timestamp: retransmissions, duplicate
 * ACKs, and a simple RTT estimate. It never re-parses and never mutates — pure projection of decode.
 */

/** One RTT sample: a data/SYN/FIN segment matched to the first ACK that covers it. */
export type RttSample = {
    segmentIndex: number
    ackIndex: number
    rtt: number
}

/** Diagnostics for one bidirectional TCP conversation. */
export type TcpStreamDiagnostic = {
    key: string
    endpointA: string
    endpointB: string
    packets: number
    retransmissions: number[]
    duplicateAcks: number[]
    rttSamples: RttSample[]
    rttMin: number | null
    rttMax: number | null
    rttMean: number | null
}

export type TcpAnalysis = {
    streams: TcpStreamDiagnostic[]
}

type TcpView = {
    source: string
    destination: string
    seq: number
    ack: number
    syn: boolean
    fin: boolean
    ackFlag: boolean
    segmentLength: number
    timestamp: number
    index: number
}

/** A segment awaiting its acknowledgement, for RTT pairing. */
type PendingSegment = {endSeq: number, timestamp: number, index: number}

/** Per-direction running state within one conversation. */
type HalfStream = {
    maxEndSeq: number
    hasMaxEndSeq: boolean
    seenSyn: boolean
    lastPureAck: number | null
    pending: PendingSegment[]
}

function find(layers: CodecDecodeResult[], id: string): CodecDecodeResult | undefined {
    return layers.find((l: CodecDecodeResult): boolean => l.id === id)
}

//RFC 1982 serial-number comparison over the 32-bit TCP sequence space (which wraps at 2^32). Returns
//true when `a` is at or before `b` in sequence order — correct across the wrap that a naive a<=b breaks.
function seqLte(a: number, b: number): boolean {
    return ((b - a) >>> 0) < 0x80000000
}

/** Project a packet to the TCP fields the analyzer needs, or null if it is not TCP-over-IP. */
function tcpViewOf(packet: AnalysisPacket, index: number): TcpView | null {
    const tcp: CodecDecodeResult | undefined = find(packet.layers, 'tcp')
    if (!tcp) return null
    const ip: CodecDecodeResult | undefined = find(packet.layers, 'ipv4') || find(packet.layers, 'ipv6')
    if (!ip) return null
    const tcpData: any = tcp.data
    const ipData: any = ip.data
    const tcpHeaderBytes: number = Number(tcpData.hdrLen) || 20
    let payload: number
    if (ip.id === 'ipv4') payload = Number(ipData.length) - (Number(ipData.hdrLen) || 20) - tcpHeaderBytes
    //IPv6's payload-length field is `plen` (bytes after the fixed 40-byte header), not `length`. This
    //over-counts if extension headers sit between IPv6 and TCP — acceptable for the common direct case.
    else payload = Number(ipData.plen) - tcpHeaderBytes
    if (!(payload >= 0)) payload = 0
    const flags: any = tcpData.flags || {}
    return {
        source: `${ipData.sip}:${tcpData.srcport}`,
        destination: `${ipData.dip}:${tcpData.dstport}`,
        seq: Number(tcpData.seq) || 0,
        ack: Number(tcpData.ack) || 0,
        syn: Boolean(flags.syn),
        fin: Boolean(flags.fin),
        ackFlag: Boolean(flags.ack),
        segmentLength: payload,
        timestamp: packet.timestamp,
        index: index
    }
}

export class TcpStreamAnalyzer {

    /**
     * Analyze all TCP conversations in the packet list. Direction-independent conversation grouping
     * matches FlowAnalyzer; per-direction state drives the diagnostics.
     */
    public analyze(packets: AnalysisPacket[]): TcpAnalysis {
        const streams: Map<string, TcpStreamDiagnostic> = new Map()
        const halves: Map<string, HalfStream> = new Map()

        packets.forEach((packet: AnalysisPacket, index: number): void => {
            const view: TcpView | null = tcpViewOf(packet, index)
            if (!view) return
            const forward: boolean = view.source <= view.destination
            const endpointA: string = forward ? view.source : view.destination
            const endpointB: string = forward ? view.destination : view.source
            const key: string = `tcp|${endpointA}|${endpointB}`

            let stream: TcpStreamDiagnostic | undefined = streams.get(key)
            if (!stream) {
                stream = {key: key, endpointA: endpointA, endpointB: endpointB, packets: 0, retransmissions: [], duplicateAcks: [], rttSamples: [], rttMin: null, rttMax: null, rttMean: null}
                streams.set(key, stream)
            }
            stream.packets++

            const forwardHalf: HalfStream = this.#half(halves, `${key}|${view.source}`)
            const reverseHalf: HalfStream = this.#half(halves, `${key}|${view.destination}`)

            //Consumed sequence span of this segment (SYN and FIN each consume one sequence number).
            const consumed: number = view.segmentLength + (view.syn ? 1 : 0) + (view.fin ? 1 : 0)
            const endSeq: number = view.seq + consumed

            //Retransmission: this segment carries sequence space we've already sent (RFC 1982 comparison
            //so long-lived streams that wrap past 2^32 are handled correctly).
            if (consumed > 0) {
                const alreadySent: boolean = forwardHalf.hasMaxEndSeq && seqLte(endSeq, forwardHalf.maxEndSeq)
                if (alreadySent || (view.syn && forwardHalf.seenSyn)) {
                    stream.retransmissions.push(index)
                } else {
                    //Only genuinely new data becomes an RTT candidate. Known simplification: if this data
                    //is later retransmitted, the original segment stays pending and its (larger) RTT is
                    //still used — no Karn's-algorithm invalidation of retransmitted samples.
                    forwardHalf.pending.push({endSeq: endSeq, timestamp: view.timestamp, index: index})
                }
                if (!forwardHalf.hasMaxEndSeq || seqLte(forwardHalf.maxEndSeq, endSeq)) {
                    forwardHalf.maxEndSeq = endSeq
                    forwardHalf.hasMaxEndSeq = true
                }
                if (view.syn) forwardHalf.seenSyn = true
            }

            //Duplicate ACK: a pure ACK (no data, no SYN/FIN) repeating the last ACK value we sent.
            if (view.ackFlag && consumed === 0) {
                if (forwardHalf.lastPureAck !== null && forwardHalf.lastPureAck === view.ack) {
                    stream.duplicateAcks.push(index)
                }
                forwardHalf.lastPureAck = view.ack
            }

            //RTT: this packet's ACK may cover segments the peer sent earlier.
            if (view.ackFlag && reverseHalf.pending.length > 0) {
                const remaining: PendingSegment[] = []
                for (const segment of reverseHalf.pending) {
                    if (seqLte(segment.endSeq, view.ack)) {
                        //ACK covers this segment (consume it either way). Only record a positive sample —
                        //out-of-order capture timestamps could otherwise yield a negative RTT.
                        if (view.timestamp >= segment.timestamp) {
                            stream.rttSamples.push({segmentIndex: segment.index, ackIndex: index, rtt: view.timestamp - segment.timestamp})
                        }
                    } else {
                        remaining.push(segment)
                    }
                }
                reverseHalf.pending = remaining
            }
        })

        for (const stream of streams.values()) this.#summarizeRtt(stream)
        return {streams: [...streams.values()]}
    }

    #half(halves: Map<string, HalfStream>, key: string): HalfStream {
        let half: HalfStream | undefined = halves.get(key)
        if (!half) {
            half = {maxEndSeq: 0, hasMaxEndSeq: false, seenSyn: false, lastPureAck: null, pending: []}
            halves.set(key, half)
        }
        return half
    }

    #summarizeRtt(stream: TcpStreamDiagnostic): void {
        if (stream.rttSamples.length === 0) return
        let min: number = Infinity
        let max: number = -Infinity
        let sum: number = 0
        for (const sample of stream.rttSamples) {
            if (sample.rtt < min) min = sample.rtt
            if (sample.rtt > max) max = sample.rtt
            sum += sample.rtt
        }
        stream.rttMin = min
        stream.rttMax = max
        stream.rttMean = sum / stream.rttSamples.length
    }
}
