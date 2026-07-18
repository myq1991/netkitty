import {CodecDecodeResult} from '@netkitty/codec'

/**
 * Cross-packet flow analysis — the first stateful, read-only subsystem, layered ABOVE the per-packet
 * codec. It consumes already-decoded packets (plus capture timestamps) and groups them into
 * conversations and endpoints, protocol-agnostically, by the network/transport n-tuple. Per-protocol
 * deep analysis (TCP retransmission/reassembly/RTT, DNS/ICMP request-response matching) layers on top
 * of this incrementally. It never re-parses — it reuses the codec's decode result.
 */

/** One captured packet handed to the analyzer: its decoded layers, capture time, and wire length. */
export type AnalysisPacket = {
    layers: CodecDecodeResult[]
    timestamp: number
    length: number
}

/** A bidirectional conversation between two endpoints, keyed direction-independently. */
export type Conversation = {
    protocol: string
    endpointA: string
    endpointB: string
    packets: number
    bytes: number
    packetsAToB: number
    packetsBToA: number
    firstTimestamp: number
    lastTimestamp: number
    packetIndices: number[]
}

/** Per-endpoint traffic totals across the whole capture. */
export type Endpoint = {
    address: string
    packets: number
    bytes: number
    txPackets: number
    txBytes: number
    rxPackets: number
    rxBytes: number
}

export type FlowAnalysis = {
    conversations: Conversation[]
    endpoints: Endpoint[]
}

type Flow = {protocol: string, source: string, destination: string}

/**
 * Derive the conversation n-tuple from a packet's decoded layers. Prefers IP + transport (tcp/udp);
 * falls back to bare IP, then to Ethernet MACs so every packet lands in some conversation.
 */
function flowOf(layers: CodecDecodeResult[]): Flow | null {
    const ip: CodecDecodeResult | undefined = layers.find((l: CodecDecodeResult): boolean => l.id === 'ipv4' || l.id === 'ipv6')
    if (ip) {
        const source: string = String((ip.data as any).sip)
        const destination: string = String((ip.data as any).dip)
        const transport: CodecDecodeResult | undefined = layers.find((l: CodecDecodeResult): boolean => l.id === 'tcp' || l.id === 'udp')
        if (transport) {
            return {
                protocol: transport.id,
                source: `${source}:${(transport.data as any).srcport}`,
                destination: `${destination}:${(transport.data as any).dstport}`
            }
        }
        return {protocol: 'ip', source: source, destination: destination}
    }
    const eth: CodecDecodeResult | undefined = layers.find((l: CodecDecodeResult): boolean => l.id === 'eth')
    if (eth) return {protocol: 'eth', source: String((eth.data as any).smac), destination: String((eth.data as any).dmac)}
    return null
}

export class FlowAnalyzer {

    /**
     * Group the packets into conversations (direction-independent) and per-endpoint totals.
     */
    public analyze(packets: AnalysisPacket[]): FlowAnalysis {
        const conversations: Map<string, Conversation> = new Map()
        const endpoints: Map<string, Endpoint> = new Map()

        packets.forEach((packet: AnalysisPacket, index: number): void => {
            const flow: Flow | null = flowOf(packet.layers)
            if (!flow) return
            //Canonical A/B ordering so A→B and B→A are one conversation.
            const forward: boolean = flow.source <= flow.destination
            const endpointA: string = forward ? flow.source : flow.destination
            const endpointB: string = forward ? flow.destination : flow.source
            const key: string = `${flow.protocol}|${endpointA}|${endpointB}`

            let conversation: Conversation | undefined = conversations.get(key)
            if (!conversation) {
                conversation = {
                    protocol: flow.protocol,
                    endpointA: endpointA,
                    endpointB: endpointB,
                    packets: 0,
                    bytes: 0,
                    packetsAToB: 0,
                    packetsBToA: 0,
                    firstTimestamp: packet.timestamp,
                    lastTimestamp: packet.timestamp,
                    packetIndices: []
                }
                conversations.set(key, conversation)
            }
            conversation.packets++
            conversation.bytes += packet.length
            if (flow.source === endpointA) conversation.packetsAToB++
            else conversation.packetsBToA++
            if (packet.timestamp < conversation.firstTimestamp) conversation.firstTimestamp = packet.timestamp
            if (packet.timestamp > conversation.lastTimestamp) conversation.lastTimestamp = packet.timestamp
            conversation.packetIndices.push(index)

            this.#accountEndpoint(endpoints, flow.source, packet.length, true)
            this.#accountEndpoint(endpoints, flow.destination, packet.length, false)
        })

        return {
            conversations: [...conversations.values()],
            endpoints: [...endpoints.values()]
        }
    }

    #accountEndpoint(endpoints: Map<string, Endpoint>, address: string, length: number, isSource: boolean): void {
        let endpoint: Endpoint | undefined = endpoints.get(address)
        if (!endpoint) {
            endpoint = {address: address, packets: 0, bytes: 0, txPackets: 0, txBytes: 0, rxPackets: 0, rxBytes: 0}
            endpoints.set(address, endpoint)
        }
        endpoint.packets++
        endpoint.bytes += length
        if (isSource) {
            endpoint.txPackets++
            endpoint.txBytes += length
        } else {
            endpoint.rxPackets++
            endpoint.rxBytes += length
        }
    }
}
