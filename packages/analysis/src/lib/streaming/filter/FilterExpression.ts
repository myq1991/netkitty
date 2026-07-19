import {CodecDecodeResult} from '@netkitty/codec'

/**
 * A single display-filter term: a bare protocol name (frame contains that layer) or a
 * `<selector> == <value>` field test. v1 covers the common selectors; the expression is the AND of
 * its predicates. Richer syntax (||, !=, ranges) is a later extension.
 */
export type FilterPredicate =
    | {kind: 'protocol', name: string}
    | {kind: 'field', selector: string, value: string}

export type FilterExpression = FilterPredicate[]

/** Parse a display filter into an AND-list of predicates. Empty input matches everything. */
export function parseFilter(input: string): FilterExpression {
    return input
        .split('&&')
        .map((part: string): string => part.trim())
        .filter((part: string): boolean => part.length > 0)
        .map(parsePredicate)
}

function parsePredicate(part: string): FilterPredicate {
    const equals: number = part.indexOf('==')
    if (equals < 0) return {kind: 'protocol', name: part.toLowerCase()}
    const selector: string = part.slice(0, equals).trim().toLowerCase()
    let value: string = part.slice(equals + 2).trim()
    if (value.length >= 2 && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith('\'') && value.endsWith('\'')))) {
        value = value.slice(1, -1)
    }
    return {kind: 'field', selector: selector, value: value}
}

/** True when the decoded layers satisfy every predicate (AND). */
export function matchesFilter(layers: CodecDecodeResult[], expression: FilterExpression): boolean {
    return expression.every((predicate: FilterPredicate): boolean => matchesPredicate(layers, predicate))
}

function layerOf(layers: CodecDecodeResult[], ...ids: string[]): CodecDecodeResult | undefined {
    return layers.find((l: CodecDecodeResult): boolean => ids.includes(l.id))
}

function field(layer: CodecDecodeResult | undefined, name: string): string | null {
    if (!layer) return null
    const value: unknown = (layer.data as any)[name]
    return value === undefined || value === null ? null : String(value)
}

function matchesPredicate(layers: CodecDecodeResult[], predicate: FilterPredicate): boolean {
    if (predicate.kind === 'protocol') return layers.some((l: CodecDecodeResult): boolean => l.id === predicate.name)
    const value: string = predicate.value
    switch (predicate.selector) {
        case 'ip.addr': return anyEquals(value, field(layerOf(layers, 'ipv4', 'ipv6'), 'sip'), field(layerOf(layers, 'ipv4', 'ipv6'), 'dip'))
        case 'ip.src': return field(layerOf(layers, 'ipv4', 'ipv6'), 'sip') === value
        case 'ip.dst': return field(layerOf(layers, 'ipv4', 'ipv6'), 'dip') === value
        case 'tcp.port': return anyEquals(value, field(layerOf(layers, 'tcp'), 'srcport'), field(layerOf(layers, 'tcp'), 'dstport'))
        case 'tcp.srcport': return field(layerOf(layers, 'tcp'), 'srcport') === value
        case 'tcp.dstport': return field(layerOf(layers, 'tcp'), 'dstport') === value
        case 'udp.port': return anyEquals(value, field(layerOf(layers, 'udp'), 'srcport'), field(layerOf(layers, 'udp'), 'dstport'))
        case 'udp.srcport': return field(layerOf(layers, 'udp'), 'srcport') === value
        case 'udp.dstport': return field(layerOf(layers, 'udp'), 'dstport') === value
        case 'eth.addr': return anyEquals(value, field(layerOf(layers, 'eth'), 'smac'), field(layerOf(layers, 'eth'), 'dmac'))
        case 'eth.src': return field(layerOf(layers, 'eth'), 'smac') === value
        case 'eth.dst': return field(layerOf(layers, 'eth'), 'dmac') === value
        default: return false
    }
}

function anyEquals(value: string, a: string | null, b: string | null): boolean {
    return a === value || b === value
}

/**
 * Try to decide a predicate from the index columns alone — the conversation key (protocol + the two
 * canonical endpoints) and the top protocol — with NO re-decode. Returns true/false when decidable,
 * or null when the frame must be decoded: direction-sensitive fields (src/dst/srcport/dstport, since
 * the key is canonicalized and loses direction), or protocols the key/topProtocol don't pin down.
 */
export function indexableEval(predicate: FilterPredicate, conversationKey: string | null, topProtocol: string): boolean | null {
    if (predicate.kind === 'protocol') {
        if (predicate.name === 'tcp' || predicate.name === 'udp') {
            if (conversationKey === null) return false
            return conversationKey.slice(0, conversationKey.indexOf('|')) === predicate.name
        }
        if (predicate.name === 'arp') return topProtocol === 'arp'
        return null
    }
    if (conversationKey === null) return false
    const bar1: number = conversationKey.indexOf('|')
    const bar2: number = conversationKey.indexOf('|', bar1 + 1)
    const proto: string = conversationKey.slice(0, bar1)
    const endpointA: string = conversationKey.slice(bar1 + 1, bar2)
    const endpointB: string = conversationKey.slice(bar2 + 1)
    switch (predicate.selector) {
        case 'ip.addr':
            if (proto !== 'tcp' && proto !== 'udp' && proto !== 'ip') return false
            return anyEquals(predicate.value, ipOf(endpointA, proto), ipOf(endpointB, proto))
        case 'tcp.port':
            if (proto !== 'tcp') return false
            return anyEquals(predicate.value, portOf(endpointA), portOf(endpointB))
        case 'udp.port':
            if (proto !== 'udp') return false
            return anyEquals(predicate.value, portOf(endpointA), portOf(endpointB))
        case 'eth.addr':
            if (proto !== 'eth') return false
            return anyEquals(predicate.value, endpointA, endpointB)
        default:
            return null
    }
}

/**
 * AND over indexableEval: false as soon as any column predicate excludes the frame (no decode); true
 * if every predicate is column-decided true; null if a predicate needs the decoded layers to confirm.
 */
export function matchesIndexed(expression: FilterExpression, conversationKey: string | null, topProtocol: string): boolean | null {
    let needsDecode: boolean = false
    for (const predicate of expression) {
        const decided: boolean | null = indexableEval(predicate, conversationKey, topProtocol)
        if (decided === false) return false
        if (decided === null) needsDecode = true
    }
    return needsDecode ? null : true
}

function ipOf(endpoint: string, proto: string): string {
    if (proto === 'ip') return endpoint
    const colon: number = endpoint.lastIndexOf(':')
    return colon < 0 ? endpoint : endpoint.slice(0, colon)
}

function portOf(endpoint: string): string {
    const colon: number = endpoint.lastIndexOf(':')
    return colon < 0 ? '' : endpoint.slice(colon + 1)
}
