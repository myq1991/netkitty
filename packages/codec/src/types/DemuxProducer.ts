/**
 * The kind of a demux value, deciding how it is normalized into a dispatch key. Normalization is
 * defined by the field's STORAGE representation, not by an output radix:
 * - `uint`   : the field stores a number (e.g. IPv4 `protocol`, IPv6 `nxt`, TCP/UDP ports) → decimal.
 * - `string` : the field already stores a normalized string (e.g. Ethernet `etherType`, a lower-case
 *              fixed-width hex string) → identity. Case-sensitive string keys (media_type, ALPN) are
 *              preserved verbatim per their standard.
 * - `guid`   : a UUID string → lower-cased.
 * - `bytes`  : a byte/hex string → lower-cased.
 */
export type DemuxProducerKind = 'uint' | 'string' | 'guid' | 'bytes'

/**
 * A demux key a layer produces for its child: the value of `field` on this layer, placed into the
 * `namespace` (e.g. `ethertype`, `ipproto`, `tcpport`). The codec reverses these declarations to route
 * the next layer, so ordering is decided entirely at runtime by the field values a packet carries.
 * Declared per-schema (replacing the old central hard-coded producer list), so adding a new demux
 * dimension is a per-protocol declaration, not a core change.
 */
export type DemuxProducer = {
    field: string
    namespace: string
    kind: DemuxProducerKind
}
