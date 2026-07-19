import {test} from 'node:test'
import assert from 'node:assert'
import {tsharkAvailable, tsharkLayers, TsharkLayers} from '../lib/Tshark'
import {AllPacketFixtureNames, LoadPacket} from '../lib/Fixtures'
import {Decode} from '../lib/RoundTrip'
import {CodecDecodeResult} from '../../src/lib/codec/types/CodecDecodeResult'

/**
 * Differential oracle: netkitty's decoded value for a field must equal Wireshark/tshark's own
 * dissection of the same bytes. This is the check that catches SYMMETRIC-wrong decodes — a field
 * read with a consistent-but-wrong interpretation round-trips perfectly yet is wrong; only an
 * independent ground truth exposes it. Mapping cost is O(protocol), not O(fixture).
 */

type ValueKind = 'mac' | 'hexcode' | 'int' | 'str'
type FieldMap = {nk: string, ts: string, kind: ValueKind}
type LayerMap = {tsLayer: string, fields: FieldMap[]}

// netkitty layer id → { tshark layer name, per-field mapping }. Only stable, authoritative fields
// are mapped (tshark shows relative TCP seq/ack and scaled windows, and compresses IPv6 addresses,
// so those are intentionally excluded).
const MAPPINGS: {[layerId: string]: LayerMap} = {
    eth: {tsLayer: 'eth', fields: [
        {nk: 'dmac', ts: 'eth.dst', kind: 'mac'},
        {nk: 'smac', ts: 'eth.src', kind: 'mac'},
        {nk: 'etherType', ts: 'eth.type', kind: 'hexcode'}
    ]},
    ipv4: {tsLayer: 'ip', fields: [
        {nk: 'version', ts: 'ip.version', kind: 'int'},
        {nk: 'hdrLen', ts: 'ip.hdr_len', kind: 'int'},
        {nk: 'length', ts: 'ip.len', kind: 'int'},
        {nk: 'ttl', ts: 'ip.ttl', kind: 'int'},
        {nk: 'protocol', ts: 'ip.proto', kind: 'int'},
        {nk: 'fragOffset', ts: 'ip.frag_offset', kind: 'int'},
        {nk: 'sip', ts: 'ip.src', kind: 'str'},
        {nk: 'dip', ts: 'ip.dst', kind: 'str'}
    ]},
    ipv6: {tsLayer: 'ipv6', fields: [
        {nk: 'version', ts: 'ipv6.version', kind: 'int'},
        {nk: 'plen', ts: 'ipv6.plen', kind: 'int'},
        {nk: 'nxt', ts: 'ipv6.nxt', kind: 'int'},
        {nk: 'hllm', ts: 'ipv6.hlim', kind: 'int'}
    ]},
    tcp: {tsLayer: 'tcp', fields: [
        {nk: 'srcport', ts: 'tcp.srcport', kind: 'int'},
        {nk: 'dstport', ts: 'tcp.dstport', kind: 'int'},
        {nk: 'window', ts: 'tcp.window_size_value', kind: 'int'}
    ]},
    udp: {tsLayer: 'udp', fields: [
        {nk: 'srcport', ts: 'udp.srcport', kind: 'int'},
        {nk: 'dstport', ts: 'udp.dstport', kind: 'int'},
        {nk: 'length', ts: 'udp.length', kind: 'int'}
    ]},
    arp: {tsLayer: 'arp', fields: [
        {nk: 'hardware.type', ts: 'arp.hw.type', kind: 'int'},
        {nk: 'hardware.size', ts: 'arp.hw.size', kind: 'int'},
        {nk: 'protocol.type', ts: 'arp.proto.type', kind: 'hexcode'},
        {nk: 'protocol.size', ts: 'arp.proto.size', kind: 'int'},
        {nk: 'opcode', ts: 'arp.opcode', kind: 'int'},
        {nk: 'sender.mac', ts: 'arp.src.hw_mac', kind: 'mac'},
        {nk: 'sender.ipv4', ts: 'arp.src.proto_ipv4', kind: 'str'},
        {nk: 'target.mac', ts: 'arp.dst.hw_mac', kind: 'mac'},
        {nk: 'target.ipv4', ts: 'arp.dst.proto_ipv4', kind: 'str'}
    ]},
    icmp: {tsLayer: 'icmp', fields: [
        {nk: 'type', ts: 'icmp.type', kind: 'int'},
        {nk: 'code', ts: 'icmp.code', kind: 'int'}
    ]},
    icmpv6: {tsLayer: 'icmpv6', fields: [
        {nk: 'type', ts: 'icmpv6.type', kind: 'int'},
        {nk: 'code', ts: 'icmpv6.code', kind: 'int'}
    ]},
    ntp: {tsLayer: 'ntp', fields: [
        // li/vn/mode live under tshark's ntp.flags_tree; getTsharkField finds them. precision is signed
        // — a strong symmetric-wrong catch (unsigned 0xe7=231 would fail against tshark's -25).
        {nk: 'li', ts: 'ntp.flags.li', kind: 'int'},
        {nk: 'vn', ts: 'ntp.flags.vn', kind: 'int'},
        {nk: 'mode', ts: 'ntp.flags.mode', kind: 'int'},
        {nk: 'stratum', ts: 'ntp.stratum', kind: 'int'},
        {nk: 'poll', ts: 'ntp.ppoll', kind: 'int'},
        {nk: 'precision', ts: 'ntp.precision', kind: 'int'}
    ]}
}

function getByPath(obj: any, dottedPath: string): unknown {
    return dottedPath.split('.').reduce((o: any, key: string): any => (o == null ? undefined : o[key]), obj)
}

// tshark places a field either directly in the layer object or inside a one-level "*_tree" child.
function getTsharkField(layer: {[field: string]: unknown} | undefined, field: string): unknown {
    if (!layer) return undefined
    if (field in layer) return layer[field]
    for (const value of Object.values(layer)) {
        if (value && typeof value === 'object' && !Array.isArray(value) && field in (value as object)) {
            return (value as {[k: string]: unknown})[field]
        }
    }
    return undefined
}

function normalizedPair(kind: ValueKind, nkValue: unknown, tsRaw: unknown): [string | number, string | number] {
    const ts: unknown = Array.isArray(tsRaw) ? tsRaw[0] : tsRaw
    switch (kind) {
        case 'mac': return [String(nkValue).toLowerCase(), String(ts).toLowerCase()]
        case 'hexcode': return [String(nkValue).replace(/^0x/i, '').toLowerCase(), String(ts).replace(/^0x/i, '').toLowerCase()]
        case 'int': return [Number(nkValue), Number(ts)]
        case 'str': return [String(nkValue), String(ts)]
    }
}

test('differential oracle: netkitty decode matches tshark for the mapped core fields', {skip: !tsharkAvailable() && 'tshark not installed'}, async (): Promise<void> => {
    const mismatches: string[] = []
    let compared: number = 0
    for (const name of AllPacketFixtureNames()) {
        const packet: Buffer = LoadPacket(name).buffer
        let layers: TsharkLayers
        try {
            layers = tsharkLayers(packet)
        } catch (e) {
            continue // tshark refused this frame; not a decode discrepancy
        }
        const decoded: CodecDecodeResult[] = await Decode(packet)
        //tshark's frame.protocols lists the dissected layer names in order. A layer that appears
        //more than once (tunneling / SRv6 / IP-in-IP) is ambiguous under -T json, which collapses
        //the duplicate key to a single last-wins object — so skip those layers rather than compare
        //netkitty's outer header against tshark's shadowed inner one.
        const protocols: string[] = String(getTsharkField(layers.frame as {[field: string]: unknown} | undefined, 'frame.protocols') || '').split(':')
        for (const layer of decoded) {
            const map: LayerMap | undefined = MAPPINGS[layer.id]
            if (!map) continue
            if (protocols.filter((protocol: string): boolean => protocol === map.tsLayer).length > 1) continue
            const tsLayer: {[field: string]: unknown} | undefined = layers[map.tsLayer] as {[field: string]: unknown} | undefined
            if (!tsLayer) continue
            for (const field of map.fields) {
                const nkValue: unknown = getByPath(layer.data, field.nk)
                const tsValue: unknown = getTsharkField(tsLayer, field.ts)
                if (nkValue === undefined || nkValue === null || tsValue === undefined) continue
                const [a, b] = normalizedPair(field.kind, nkValue, tsValue)
                compared++
                if (a !== b) mismatches.push(`${name} · ${layer.id}.${field.nk}: netkitty=${JSON.stringify(a)} tshark=${JSON.stringify(b)} (${field.ts})`)
            }
        }
    }
    assert.ok(compared > 50, `expected the oracle to compare many fields, only compared ${compared}`)
    assert.deepStrictEqual(mismatches, [], `netkitty disagreed with tshark on ${mismatches.length} field(s):\n  ${mismatches.join('\n  ')}`)
})
