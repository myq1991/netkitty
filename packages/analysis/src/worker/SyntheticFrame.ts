import {CodecDecodeResult} from '@netkitty/codec'

/**
 * Rebuild the five-tuple layers of a frame from its index columns (conversation key + direction bit),
 * without decoding the packet. Feeds indexOnly reducers on replay so they skip re-decode entirely.
 * Only the fields flowOf reads are reconstructed (sip/dip/srcport/dstport or smac/dmac); deep fields
 * are absent by design — that is why only reducers that declare indexOnly may be fed these frames.
 */
export function synthesizeLayers(conversationKey: string, directionForward: number): CodecDecodeResult[] {
    const bar1: number = conversationKey.indexOf('|')
    const bar2: number = conversationKey.indexOf('|', bar1 + 1)
    const proto: string = conversationKey.slice(0, bar1)
    const endpointA: string = conversationKey.slice(bar1 + 1, bar2)
    const endpointB: string = conversationKey.slice(bar2 + 1)
    const source: string = directionForward ? endpointA : endpointB
    const destination: string = directionForward ? endpointB : endpointA
    if (proto === 'tcp' || proto === 'udp') {
        const s: {ip: string, port: string} = splitEndpoint(source)
        const d: {ip: string, port: string} = splitEndpoint(destination)
        const ipId: string = s.ip.includes(':') ? 'ipv6' : 'ipv4'
        return [layer('eth', {}), layer(ipId, {sip: s.ip, dip: d.ip}), layer(proto, {srcport: s.port, dstport: d.port})]
    }
    if (proto === 'ip') {
        const ipId: string = source.includes(':') ? 'ipv6' : 'ipv4'
        return [layer('eth', {}), layer(ipId, {sip: source, dip: destination})]
    }
    if (proto === 'eth') return [layer('eth', {smac: source, dmac: destination})]
    return [layer('eth', {})]
}

function layer(id: string, data: Record<string, unknown>): CodecDecodeResult {
    return {id: id, name: id, nickname: id, protocol: true, errors: [], data: data as any}
}

function splitEndpoint(endpoint: string): {ip: string, port: string} {
    const colon: number = endpoint.lastIndexOf(':')
    return colon < 0 ? {ip: endpoint, port: ''} : {ip: endpoint.slice(0, colon), port: endpoint.slice(colon + 1)}
}
