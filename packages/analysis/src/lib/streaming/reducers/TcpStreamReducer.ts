import {CodecDecodeResult} from '@netkitty/codec'
import {Frame} from '../types/Frame'
import {UpdateContext} from '../types/UpdateContext'
import {IAnalysisReducer} from '../interfaces/IAnalysisReducer'
import {RttSample, TcpStreamDiagnostic} from '../../analysis/TcpStreamAnalyzer'

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

type PendingSegment = {endSeq: number, timestamp: number, index: number}

type HalfStream = {maxEndSeq: number, hasMaxEndSeq: boolean, seenSyn: boolean, lastPureAck: number | null, pending: PendingSegment[]}

function find(layers: CodecDecodeResult[], id: string): CodecDecodeResult | undefined {
    return layers.find((l: CodecDecodeResult): boolean => l.id === id)
}

//RFC 1982 serial comparison over the 32-bit sequence space (wraps at 2^32): a at/before b.
function seqLte(a: number, b: number): boolean {
    return ((b - a) >>> 0) < 0x80000000
}

/** Project a frame to the TCP fields the reducer needs, or null if it is not TCP-over-IP. */
function tcpViewOf(frame: Frame): TcpView | null {
    const tcp: CodecDecodeResult | undefined = find(frame.layers, 'tcp')
    if (!tcp) return null
    const ip: CodecDecodeResult | undefined = find(frame.layers, 'ipv4') || find(frame.layers, 'ipv6')
    if (!ip) return null
    const tcpData: any = tcp.data
    const ipData: any = ip.data
    const tcpHeaderBytes: number = Number(tcpData.hdrLen) || 20
    let payload: number
    if (ip.id === 'ipv4') payload = Number(ipData.length) - (Number(ipData.hdrLen) || 20) - tcpHeaderBytes
    //IPv6 uses plen (bytes after the 40-byte header), not length; over-counts with extension headers.
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
        timestamp: frame.timestamp,
        index: frame.index
    }
}

function summarizeRtt(stream: TcpStreamDiagnostic): void {
    if (stream.rttSamples.length === 0) {
        stream.rttMin = null
        stream.rttMax = null
        stream.rttMean = null
        return
    }
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

/**
 * Streaming TCP stream diagnostics — same logic as TcpStreamAnalyzer, per-frame: retransmissions
 * (sequence space already sent, RFC 1982-aware), duplicate ACKs, and RTT (a segment matched to the
 * first ACK covering it). result() is a rolling snapshot; RTT min/max/mean are recomputed at result().
 * State grows per unique TCP stream — watch governance (eviction) layers on in a later step.
 */
export class TcpStreamReducer implements IAnalysisReducer<TcpStreamDiagnostic[]> {

    public readonly needs: string[] = ['ipv4', 'ipv6', 'tcp']

    readonly #streams: Map<string, TcpStreamDiagnostic> = new Map<string, TcpStreamDiagnostic>()

    readonly #halves: Map<string, HalfStream> = new Map<string, HalfStream>()

    public update(frame: Frame, context: UpdateContext): void {
        void context
        const view: TcpView | null = tcpViewOf(frame)
        if (!view) return
        const forward: boolean = view.source <= view.destination
        const endpointA: string = forward ? view.source : view.destination
        const endpointB: string = forward ? view.destination : view.source
        const key: string = `tcp|${endpointA}|${endpointB}`

        let stream: TcpStreamDiagnostic | undefined = this.#streams.get(key)
        if (!stream) {
            stream = {key: key, endpointA: endpointA, endpointB: endpointB, packets: 0, retransmissions: [], duplicateAcks: [], rttSamples: [], rttMin: null, rttMax: null, rttMean: null}
            this.#streams.set(key, stream)
        }
        stream.packets++

        const forwardHalf: HalfStream = this.#half(`${key}|${view.source}`)
        const reverseHalf: HalfStream = this.#half(`${key}|${view.destination}`)

        const consumed: number = view.segmentLength + (view.syn ? 1 : 0) + (view.fin ? 1 : 0)
        const endSeq: number = view.seq + consumed

        if (consumed > 0) {
            const alreadySent: boolean = forwardHalf.hasMaxEndSeq && seqLte(endSeq, forwardHalf.maxEndSeq)
            if (alreadySent || (view.syn && forwardHalf.seenSyn)) {
                stream.retransmissions.push(view.index)
            } else {
                forwardHalf.pending.push({endSeq: endSeq, timestamp: view.timestamp, index: view.index})
            }
            if (!forwardHalf.hasMaxEndSeq || seqLte(forwardHalf.maxEndSeq, endSeq)) {
                forwardHalf.maxEndSeq = endSeq
                forwardHalf.hasMaxEndSeq = true
            }
            if (view.syn) forwardHalf.seenSyn = true
        }

        if (view.ackFlag && consumed === 0) {
            if (forwardHalf.lastPureAck !== null && forwardHalf.lastPureAck === view.ack) {
                stream.duplicateAcks.push(view.index)
            }
            forwardHalf.lastPureAck = view.ack
        }

        if (view.ackFlag && reverseHalf.pending.length > 0) {
            const remaining: PendingSegment[] = []
            for (const segment of reverseHalf.pending) {
                if (seqLte(segment.endSeq, view.ack)) {
                    if (view.timestamp >= segment.timestamp) {
                        const sample: RttSample = {segmentIndex: segment.index, ackIndex: view.index, rtt: view.timestamp - segment.timestamp}
                        stream.rttSamples.push(sample)
                    }
                } else {
                    remaining.push(segment)
                }
            }
            reverseHalf.pending = remaining
        }
    }

    public result(): TcpStreamDiagnostic[] {
        for (const stream of this.#streams.values()) summarizeRtt(stream)
        return [...this.#streams.values()]
    }

    public reset(): void {
        this.#streams.clear()
        this.#halves.clear()
    }

    #half(key: string): HalfStream {
        let half: HalfStream | undefined = this.#halves.get(key)
        if (!half) {
            half = {maxEndSeq: 0, hasMaxEndSeq: false, seenSyn: false, lastPureAck: null, pending: []}
            this.#halves.set(key, half)
        }
        return half
    }
}
