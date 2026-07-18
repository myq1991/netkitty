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
