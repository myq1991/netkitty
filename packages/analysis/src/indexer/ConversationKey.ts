import {CodecDecodeResult} from '@netkitty/codec'

/** The directional n-tuple of a frame, before canonicalization. */
export type ConversationFlow = {
    protocol: string
    source: string
    destination: string
}

/**
 * Derive the conversation n-tuple from a frame's decoded layers. Prefers IP + transport (tcp/udp),
 * falls back to bare IP, then Ethernet MACs.
 */
export function flowOf(layers: CodecDecodeResult[]): ConversationFlow | null {
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

/** Canonical, direction-independent key so A→B and B→A collapse to one conversation. */
export function canonicalConversationKey(flow: ConversationFlow): string {
    const forward: boolean = flow.source <= flow.destination
    const a: string = forward ? flow.source : flow.destination
    const b: string = forward ? flow.destination : flow.source
    return `${flow.protocol}|${a}|${b}`
}

/** The innermost real protocol id (last layer with protocol === true), skipping RawData tails. */
export function topProtocolOf(layers: CodecDecodeResult[]): string {
    for (let i: number = layers.length - 1; i >= 0; i--) {
        if (layers[i].protocol) return layers[i].id
    }
    return layers.length > 0 ? layers[layers.length - 1].id : 'unknown'
}

/** FNV-1a 32-bit hash — a compact numeric key for the conversation column. */
export function hash32(input: string): number {
    let hash: number = 0x811c9dc5
    for (let i: number = 0; i < input.length; i++) {
        hash ^= input.charCodeAt(i)
        hash = (hash + ((hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24))) >>> 0
    }
    return hash >>> 0
}
