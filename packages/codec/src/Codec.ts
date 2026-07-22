import {CodecModuleConstructor} from './types/CodecModuleConstructor'
import {CodecModule} from './types/CodecModule'
import {CodecDecodeResult} from './types/CodecDecodeResult'
import {CodecEncodeInput} from './types/CodecEncodeInput'
import {CodecErrorInfo} from './types/CodecErrorInfo'
import {PostHandlerItem} from './types/PostHandlerItem'
import {CodecData} from './types/CodecData'
import {FlexibleObject} from './lib/FlexibleObject'
import {CodecSchema} from './types/CodecSchema'
import {ProcessPacketDecodePostHandlers, ProcessPacketEncodePostHandlers} from './lib/ProcessPacketPostHandlers'
import {CodecEncodeResult} from './types/CodecEncodeResult'
import {RawData} from './headers/RawData'
import {NextLayer, ConsistencyIssue} from './types/LayerGraph'
import {DissectionField, DissectionLayer} from './types/Dissection'
import {FieldByteRange} from './abstracts/BaseHeader'
import {ProtocolJSONSchema} from './schema/ProtocolJSONSchema'
import {DemuxProducer, DemuxProducerKind} from './types/DemuxProducer'
import * as packetHeaders from './PacketHeaders'

/**
 * The schema-driven packet codec: the entry point a consumer uses to turn bytes into a
 * layered field tree and back.
 *
 * `decode(bytes)` walks the packet layer by layer, selecting each next header by an O(1)
 * dispatch table keyed on the previous layer's demux value (`ethertype:`/`ipproto:`/
 * `tcpport:`…), falling back to a content-heuristic chain for headers that must inspect
 * their own bytes (TLS, IEC104, tunnels), and finally to `RawData` — so decode never
 * throws and always yields a best-effort result plus a field-path-addressed error list.
 * `encode(layers)` looks each layer up by protocol id and re-emits it in the given order.
 * Cross-layer fixups (lengths, checksums) run as post-handlers afterwards. Read-only
 * projections over the same decode are exposed via `dissect()`, `summary()`,
 * `allowedNextLayers()`, `childDiscriminator()` and `checkConsistency()`.
 */
export class Codec {

    readonly #codecModuleConstructors: CodecModuleConstructor[] = []

    readonly #codecSchemas: CodecSchema[] = []

    /**
     * Dispatch table: demux key (e.g. 'ethertype:0800', 'ipproto:6') → codec candidates.
     * Built once at construction for O(1) next-layer selection during decode.
     */
    readonly #dispatchTable: Map<string, CodecModuleConstructor[]> = new Map()

    /**
     * Content-heuristic codecs: headers without demux keys that must inspect
     * their own bytes to match (TLS, IEC104, ethernet tunnels, and any custom
     * codec that did not declare matchKeys). Tried linearly only when the
     * dispatch table misses. Kept in registration order.
     */
    readonly #heuristicCodecs: CodecModuleConstructor[] = []

    /**
     * Range demux table: namespace → sorted list of {lo, hi, codec} for matchKeys like
     * 'tcpport:6000-6063'. Checked when an exact bucket lookup for that namespace's value misses, so a
     * protocol can claim a port range without expanding it into thousands of exact keys.
     */
    readonly #rangeTable: Map<string, {lo: number, hi: number, codecModuleConstructor: CodecModuleConstructor}[]> = new Map()

    /**
     * Encode lookup: PROTOCOL_ID → codec constructor. Built once alongside the dispatch table so
     * #encode resolves each input layer's constructor in O(1) instead of scanning HEADER_CODECS with a
     * `.find` reading the `PROTOCOL_ID` getter — which constructs a throwaway instance (and, for the
     * unmigrated headers, rebuilds SCHEMA) per candidate, i.e. ~O(headers) redundant constructions per
     * encoded layer. First registration wins, preserving the previous `.find` first-match semantics.
     */
    readonly #codecConstructorById: Map<string, CodecModuleConstructor> = new Map()

    /**
     * The RawData catch-all. Not part of the dispatch table or heuristic list;
     * used explicitly as the final fallback so decode never fails.
     */
    #rawDataCodec: CodecModuleConstructor = RawData

    protected get HEADER_CODECS(): CodecModuleConstructor[] {
        return this.#codecModuleConstructors
    }

    public get CODEC_SCHEMAS(): CodecSchema[] {
        return this.#codecSchemas
    }

    /**
     * Build a codec over the built-in protocol headers, optionally extended with custom ones.
     * Each custom codec whose `PROTOCOL_ID` matches a built-in replaces it in place; the rest
     * are appended. The dispatch table and heuristic chain are then built from the final set.
     * @param codecModuleConstructors custom header codecs to override built-ins or add new protocols
     */
    constructor(codecModuleConstructors: CodecModuleConstructor[] = []) {
        this.#codecModuleConstructors = this.loadHeaderCodecs()
        if (codecModuleConstructors) {
            const replaced: CodecModuleConstructor[] = []
            codecModuleConstructors.forEach((codecModuleConstructor: CodecModuleConstructor) => {
                const id: string = codecModuleConstructor.PROTOCOL_ID
                this.#codecModuleConstructors.forEach((HEADER_CODEC: CodecModuleConstructor, index: number, array: CodecModuleConstructor[]): void => {
                    if (HEADER_CODEC.PROTOCOL_ID === id) {
                        array[index] = codecModuleConstructor
                        replaced.push(codecModuleConstructor)
                    }
                })
            })
            codecModuleConstructors
                .filter((codecModuleConstructor: CodecModuleConstructor): boolean => !replaced.includes(codecModuleConstructor))
                .forEach((codecModuleConstructor: CodecModuleConstructor): number => this.#codecModuleConstructors.push(codecModuleConstructor))
        }
        this.#codecSchemas = this.loadCodecSchemas()
        this.buildDispatchTable()
    }

    /**
     * Load codec schemas
     * @protected
     */
    protected loadCodecSchemas(): CodecSchema[] {
        return this.HEADER_CODECS.map((codecModuleConstructor: CodecModuleConstructor): CodecSchema => ({
            id: codecModuleConstructor.PROTOCOL_ID,
            name: codecModuleConstructor.PROTOCOL_NAME,
            schema: codecModuleConstructor.PROTOCOL_SCHEMA
        }))
    }

    /**
     * Load header codecs
     * @protected
     */
    protected loadHeaderCodecs(): CodecModuleConstructor[] {
        return [...Object.values(packetHeaders)]
    }

    /**
     * Build the dispatch table and heuristic list from the registered codecs.
     * Called once after all codecs (built-in + custom overrides/additions) are
     * assembled. RawData is pulled out as the explicit fallback.
     * @protected
     */
    protected buildDispatchTable(): void {
        this.#dispatchTable.clear()
        this.#heuristicCodecs.length = 0
        this.#rangeTable.clear()
        this.#codecConstructorById.clear()
        for (const codecModuleConstructor of this.HEADER_CODECS) {
            //Read PROTOCOL_ID once (the getter builds a throwaway instance) and register it for O(1)
            //encode lookup; keep the first registration so this matches the old `.find` first-match.
            const protocolId: string = codecModuleConstructor.PROTOCOL_ID
            if (!this.#codecConstructorById.has(protocolId)) this.#codecConstructorById.set(protocolId, codecModuleConstructor)
            if (protocolId === RawData.PROTOCOL_ID) {
                this.#rawDataCodec = codecModuleConstructor
                continue
            }
            const matchKeys: string[] = codecModuleConstructor.MATCH_KEYS
            const keyed: boolean = !!(matchKeys && matchKeys.length)
            if (keyed) {
                for (const matchKey of matchKeys) {
                    const range: {namespace: string, lo: number, hi: number} | null = this.#parseRangeKey(matchKey)
                    if (range) {
                        const list: {lo: number, hi: number, codecModuleConstructor: CodecModuleConstructor}[] | undefined = this.#rangeTable.get(range.namespace)
                        const entry: {lo: number, hi: number, codecModuleConstructor: CodecModuleConstructor} = {lo: range.lo, hi: range.hi, codecModuleConstructor: codecModuleConstructor}
                        if (list) list.push(entry)
                        else this.#rangeTable.set(range.namespace, [entry])
                        continue
                    }
                    const bucket: CodecModuleConstructor[] | undefined = this.#dispatchTable.get(matchKey)
                    if (bucket) bucket.push(codecModuleConstructor)
                    else this.#dispatchTable.set(matchKey, [codecModuleConstructor])
                }
            }
            //Also list in the heuristic fallback when unkeyed, OR when a keyed codec opts in — so a
            //content-signed protocol on its well-known port takes the O(1) bucket yet still matches on
            //any other port. A codec may therefore appear in both a bucket and the heuristic chain.
            if (!keyed || codecModuleConstructor.HEURISTIC_FALLBACK) {
                this.#heuristicCodecs.push(codecModuleConstructor)
            }
        }
        //Deterministic ordering: higher matchPriority is tried first within each bucket and within the
        //heuristic chain; Array.sort is stable in Node, so ties keep registration order (all default 0
        //→ order unchanged, so existing behavior is byte-identical).
        for (const bucket of this.#dispatchTable.values()) this.#sortByPriority(bucket)
        for (const ranges of this.#rangeTable.values()) ranges.sort((a: {codecModuleConstructor: CodecModuleConstructor}, b: {codecModuleConstructor: CodecModuleConstructor}): number => b.codecModuleConstructor.MATCH_PRIORITY - a.codecModuleConstructor.MATCH_PRIORITY)
        this.#sortByPriority(this.#heuristicCodecs)
    }

    #sortByPriority(codecModuleConstructors: CodecModuleConstructor[]): void {
        codecModuleConstructors.sort((a: CodecModuleConstructor, b: CodecModuleConstructor): number => b.MATCH_PRIORITY - a.MATCH_PRIORITY)
    }

    /**
     * Parse a range matchKey 'namespace:LO-HI' (decimal, LO<=HI) into its parts, or null if it is a
     * plain exact key. Only integer ranges are supported (ports).
     * @private
     */
    #parseRangeKey(matchKey: string): {namespace: string, lo: number, hi: number} | null {
        const match: RegExpMatchArray | null = matchKey.match(/^([^:]+):(\d+)-(\d+)$/)
        if (!match) return null
        const lo: number = Number(match[2])
        const hi: number = Number(match[3])
        if (lo > hi) return null
        return {namespace: match[1], lo: lo, hi: hi}
    }

    /**
     * Derive the demux keys exposed by the previously decoded layer.
     * The layer order is decided entirely at runtime from these values, so a
     * packet with or without a given header (e.g. an IPv6 packet with or
     * without a Hop-by-Hop header) is handled purely by what its next-header
     * fields actually say — the table itself encodes no layer ordering.
     *
     * etherType → 'ethertype:<value>' namespace.
     * protocol AND nxt → shared 'ipproto:<value>' namespace, so a header
     * registered under 'ipproto:6' (TCP) is reachable above both IPv4
     * (protocol) and IPv6 (nxt).
     * @param prevCodecModule
     * @protected
     */
    protected computeDemuxKeys(prevCodecModule: CodecModule | undefined): string[] {
        if (!prevCodecModule) return []
        //Read the declaration off the already-constructed prev instance (not the static getter, which
        //would build a fresh instance + SCHEMA per decoded layer on the hot path).
        const producers: DemuxProducer[] = prevCodecModule.demuxProducers
        const instance: FlexibleObject = prevCodecModule.instance
        const keys: string[] = []
        for (const producer of producers) {
            const raw: any = (instance as any)[producer.field].getValue()
            if (raw === undefined || raw === null) continue
            keys.push(`${producer.namespace}:${this.#normalizeDemux(raw, producer.kind)}`)
        }
        return keys
    }

    /**
     * Normalize a demux value into its dispatch-key form by the field's STORAGE representation (never
     * by an output radix). uint → decimal string (protocol/nxt/ports are numbers); string → identity
     * (etherType already stores a lower-case fixed-width hex string; case-sensitive maps kept verbatim);
     * guid/bytes → lower-cased. Must produce exactly the string a matchKeys entry uses.
     * @private
     */
    #normalizeDemux(raw: any, kind: DemuxProducerKind): string {
        switch (kind) {
            case 'uint':
                return String(raw)
            case 'guid':
            case 'bytes':
                return String(raw).toLowerCase()
            case 'string':
            default:
                return String(raw)
        }
    }

    /**
     * Select the codec for the next layer: dispatch table → content-heuristic
     * list → RawData. Never returns undefined; RawData always matches unknown
     * or malformed data, so decode cannot fail.
     * @param codecData
     * @param codecModules
     * @protected
     */
    protected selectCodec(codecData: CodecData, codecModules: CodecModule[], rootLinktype?: number): CodecModuleConstructor {
        const prevCodecModule: CodecModule | undefined = codecModules[codecModules.length - 1]
        //Root layer: when a link type is supplied (a pcap DLT value), dispatch the first layer by a
        //'linktype:<dlt>' key so a non-Ethernet link (802.11+radiotap, etc.) selects the right root.
        //Without one, the root falls to the heuristic list (Ethernet matches when there is no parent),
        //so the default decode(packet) behaviour is unchanged.
        const demuxKeys: string[] = (codecModules.length === 0 && rootLinktype !== undefined && rootLinktype !== null)
            ? [`linktype:${rootLinktype}`]
            : this.computeDemuxKeys(prevCodecModule)
        //1. Dispatch table: O(1) lookup by the previous layer's demux value. Every candidate is
        //confirmed by match(), singleton buckets included — a header's own guard is never skipped, so
        //a demux key that is ambiguous across parents (e.g. 'ipproto:0' produced by both an IPv4
        //protocol=0 and an IPv6 next-header=0) still routes correctly, because IPv6 Hop-by-Hop's
        //match() rejects a non-IPv6 parent. Transport headers accept their demux value from both IPv4
        //(protocol) and IPv6 (nxt); see TCP/UDP match().
        for (const matchKey of demuxKeys) {
            const bucket: CodecModuleConstructor[] | undefined = this.#dispatchTable.get(matchKey)
            if (bucket) {
                for (const codecModuleConstructor of bucket) {
                    if (codecModuleConstructor.MATCH(codecData, codecModules)) return codecModuleConstructor
                }
            }
            //Range table: a codec claiming e.g. 'tcpport:6000-6063' matches any value in [lo,hi].
            if (this.#rangeTable.size > 0) {
                const colon: number = matchKey.indexOf(':')
                const ranges: {lo: number, hi: number, codecModuleConstructor: CodecModuleConstructor}[] | undefined = colon > 0 ? this.#rangeTable.get(matchKey.substring(0, colon)) : undefined
                if (ranges) {
                    const value: number = Number(matchKey.substring(colon + 1))
                    if (Number.isInteger(value)) {
                        for (const range of ranges) {
                            if (value >= range.lo && value <= range.hi && range.codecModuleConstructor.MATCH(codecData, codecModules)) return range.codecModuleConstructor
                        }
                    }
                }
            }
        }
        //2. Content-heuristic codecs (tunnels, TCP-payload protocols, undeclared customs).
        for (const codecModuleConstructor of this.#heuristicCodecs) {
            if (codecModuleConstructor.MATCH(codecData, codecModules)) return codecModuleConstructor
        }
        //3. RawData fallback: always matches, so unknown/malformed data still decodes.
        return this.#rawDataCodec
    }

    /**
     * Internal encode headers to packet
     * @param inputs
     * @param errors
     * @private
     */
    async #encode(inputs: CodecEncodeInput[], errors: CodecErrorInfo[] = []): Promise<CodecData> {
        const codecData: CodecData = {
            packet: Buffer.from([]),
            startPos: 0,
            postHandlers: []
        }
        const codecModules: CodecModule[] = []
        for (const input of inputs) {
            const codecModuleConstructor: CodecModuleConstructor | undefined = this.#codecConstructorById.get(input.id)
            if (!codecModuleConstructor) {
                errors.push({id: input.id, path: '', message: `Unknown protocol id: ${input.id}`})
                continue
            }
            const codecModule: CodecModule = codecModuleConstructor.CREATE_INSTANCE(codecData, codecModules)
            codecModule.instance = new FlexibleObject(codecModule.validate(input.data))
            await codecModule.encode()
            codecModule.errors.forEach((errorInfo: CodecErrorInfo): number => errors.push(errorInfo))
            codecData.startPos = codecModule.endPos
            codecModules.push(codecModule)
        }
        return codecData
    }

    /**
     * Internal decode packet
     * @param codecData
     * @param codecModules
     * @private
     */
    async #decode(codecData: CodecData, codecModules: CodecModule[] = [], collectRanges: boolean = false, rootLinktype?: number): Promise<void> {
        //rootLinktype only steers the first (root) layer; deeper layers demux off their parent.
        const codecModuleConstructor: CodecModuleConstructor = this.selectCodec(codecData, codecModules, codecModules.length === 0 ? rootLinktype : undefined)
        const codecModule: CodecModule = codecModuleConstructor.CREATE_INSTANCE(codecData, codecModules)
        //Dissect pass: record each field's byte span. Off for normal decode, so the hot path is untouched.
        if (collectRanges) codecModule.enableByteRangeTracking()
        await codecModule.decode()
        codecData.startPos = codecModule.endPos
        codecModules.push(codecModule)
        if (codecData.startPos >= codecData.packet.length) return
        return this.#decode(codecData, codecModules, collectRanges, rootLinktype)
    }

    /**
     * Decode packet
     * @param packet
     * @param linktype optional pcap link-layer type (DLT) to select the root layer (e.g. 1 = Ethernet,
     *   127 = radiotap). Omit to use the default Ethernet-first root — existing callers are unaffected.
     */
    public async decode(packet: Buffer, linktype?: number): Promise<CodecDecodeResult[]> {
        const codecData: CodecData = {
            packet: packet,
            startPos: 0,
            postHandlers: []
        }
        const codecModules: CodecModule[] = []
        await this.#decode(codecData, codecModules, false, linktype)
        const postDecodeHandlers: PostHandlerItem[] = ProcessPacketDecodePostHandlers(codecData.postHandlers)
        let postDecodeHandler: PostHandlerItem | undefined = postDecodeHandlers.shift()
        while (postDecodeHandler) {
            await postDecodeHandler.handler()
            postDecodeHandler = postDecodeHandlers.shift()
        }
        return codecModules.map((codecModule: CodecModule): CodecDecodeResult => ({
            id: codecModule.id,
            name: codecModule.name,
            nickname: codecModule.nickname,
            protocol: codecModule.isProtocol,
            errors: codecModule.errors,
            data: codecModule.instance.getValue()
        }))
    }

    /**
     * Encode packet
     * @param inputs
     */
    public async encode(inputs: CodecEncodeInput[]): Promise<CodecEncodeResult> {
        const errors: CodecErrorInfo[] = []
        const codecData: CodecData = await this.#encode(inputs, errors)
        const postEncodeHandlers: PostHandlerItem[] = ProcessPacketEncodePostHandlers(codecData.postHandlers)
        let postEncodeHandler: PostHandlerItem | undefined = postEncodeHandlers.shift()
        while (postEncodeHandler) {
            await postEncodeHandler.handler()
            postEncodeHandler = postEncodeHandlers.shift()
        }
        return {
            packet: codecData.packet,
            errors: errors
        }
    }

    /**
     * Producer fields a layer's schema declares (etherType / protocol / nxt) — the fields whose
     * value decode uses to pick the next layer. Basis for walking the parent→child graph forward.
     * @param layerId
     * @private
     */
    #producersOf(layerId: string): DemuxProducer[] {
        const codecModuleConstructor: CodecModuleConstructor | undefined = this.HEADER_CODECS.find((codec: CodecModuleConstructor): boolean => codec.PROTOCOL_ID === layerId)
        return codecModuleConstructor ? codecModuleConstructor.DEMUX_PRODUCERS : []
    }

    /**
     * Editor helper (read-only projection over the same demux graph decode uses): the layers that
     * may follow `parentLayerId`, each tagged with the {field,value} to set on the parent so decode
     * would route to it. Derived by reversing the dispatch table over the parent's producer fields.
     * RawData is always appended as the custom/fallback layer that may follow anything.
     * @param parentLayerId
     */
    public allowedNextLayers(parentLayerId: string): NextLayer[] {
        const result: NextLayer[] = []
        const seen: Set<string> = new Set()
        for (const producer of this.#producersOf(parentLayerId)) {
            const prefix: string = `${producer.namespace}:`
            for (const [key, constructors] of this.#dispatchTable) {
                if (!key.startsWith(prefix)) continue
                const raw: string = key.substring(prefix.length)
                const value: string | number = producer.kind === 'uint' ? Number(raw) : raw
                for (const codecModuleConstructor of constructors) {
                    //Dedup by protocol id: a parent with two producers in one namespace (TCP's src+dst
                    //port) must not list the same child twice. The first producer encountered wins the
                    //discriminator hint (refining src-vs-dst direction is a later step).
                    if (seen.has(codecModuleConstructor.PROTOCOL_ID)) continue
                    seen.add(codecModuleConstructor.PROTOCOL_ID)
                    result.push({id: codecModuleConstructor.PROTOCOL_ID, name: codecModuleConstructor.PROTOCOL_NAME, discriminator: {field: producer.field, value: value}})
                }
            }
            //Range-keyed children in this namespace: hint the low end of the range as the discriminator.
            const ranges: {lo: number, codecModuleConstructor: CodecModuleConstructor}[] | undefined = this.#rangeTable.get(producer.namespace)
            if (ranges) {
                for (const range of ranges) {
                    if (seen.has(range.codecModuleConstructor.PROTOCOL_ID)) continue
                    seen.add(range.codecModuleConstructor.PROTOCOL_ID)
                    result.push({id: range.codecModuleConstructor.PROTOCOL_ID, name: range.codecModuleConstructor.PROTOCOL_NAME, discriminator: {field: producer.field, value: range.lo}})
                }
            }
        }
        result.push({id: this.#rawDataCodec.PROTOCOL_ID, name: this.#rawDataCodec.PROTOCOL_NAME, discriminator: null})
        return result
    }

    /**
     * The {field,value} to set on `parentLayerId` so `childLayerId` follows it — used to auto-fill
     * the parent discriminator when a child is added, and to suggest a fix for a consistency issue.
     * Null when the child is not reachable from that parent via the demux graph (RawData, or a
     * content-heuristic child such as TLS/IEC104 whose match is port/content based).
     * @param parentLayerId
     * @param childLayerId
     */
    public childDiscriminator(parentLayerId: string, childLayerId: string): {field: string, value: string | number} | null {
        for (const next of this.allowedNextLayers(parentLayerId)) {
            if (next.id === childLayerId && next.discriminator) return next.discriminator
        }
        return null
    }

    /**
     * Editor helper: report parent layers whose discriminator field does not point at the child that
     * actually follows (e.g. eth.etherType says IPv6 but the next layer is IPv4). This is advisory
     * only — encode never blocks on it, since a deliberately-inconsistent packet is a valid crafted
     * packet. Only demux-based relationships are checked; content-heuristic children (TLS/IEC104) are
     * not flagged. RawData may follow anything and is never flagged.
     * @param decoded
     */
    public checkConsistency(decoded: CodecDecodeResult[]): ConsistencyIssue[] {
        const issues: ConsistencyIssue[] = []
        for (let i: number = 0; i < decoded.length - 1; i++) {
            const parent: CodecDecodeResult = decoded[i]
            const child: CodecDecodeResult = decoded[i + 1]
            if (child.id === this.#rawDataCodec.PROTOCOL_ID) continue
            //A content-heuristic child (no matchKeys, or heuristicFallback dual) is legitimately
            //reachable off its well-known demux value (e.g. TLS on a non-443 port). Never flag it as
            //inconsistent with the parent's discriminator — it is matched by content, not by the key.
            if (this.#heuristicCodecs.some((codecModuleConstructor: CodecModuleConstructor): boolean => codecModuleConstructor.PROTOCOL_ID === child.id)) continue
            //A parent may expose several producers in one namespace (TCP's src+dst port). The child is
            //consistent if ANY of them routes to it; only flag when NONE do. Report the first producer
            //that actually carried a value as the representative.
            const producers: DemuxProducer[] = this.#producersOf(parent.id)
            let representative: {producer: DemuxProducer, actual: any} | undefined = undefined
            let reachable: boolean = false
            for (const producer of producers) {
                const actual: any = (parent.data as any)[producer.field]
                if (actual === undefined || actual === null) continue
                if (!representative) representative = {producer: producer, actual: actual}
                const bucket: CodecModuleConstructor[] | undefined = this.#dispatchTable.get(`${producer.namespace}:${this.#normalizeDemux(actual, producer.kind)}`)
                if (bucket && bucket.some((codecModuleConstructor: CodecModuleConstructor): boolean => codecModuleConstructor.PROTOCOL_ID === child.id)) { reachable = true; break }
                const ranges: {lo: number, hi: number, codecModuleConstructor: CodecModuleConstructor}[] | undefined = this.#rangeTable.get(producer.namespace)
                if (ranges && Number.isInteger(Number(actual)) && ranges.some((range: {lo: number, hi: number, codecModuleConstructor: CodecModuleConstructor}): boolean => Number(actual) >= range.lo && Number(actual) <= range.hi && range.codecModuleConstructor.PROTOCOL_ID === child.id)) { reachable = true; break }
            }
            if (reachable || !representative) continue
            issues.push({
                index: i,
                parentId: parent.id,
                childId: child.id,
                field: representative.producer.field,
                actual: representative.actual,
                suggestion: this.childDiscriminator(parent.id, child.id),
                message: `${parent.id}.${representative.producer.field}=${representative.actual} 与下一层 '${child.id}' 不符`
            })
        }
        return issues
    }

    /**
     * Wireshark-style dissection: decode the packet with byte-range tracking on, then project each
     * layer into a field tree carrying the value, the schema label, the exact packet bytes the field
     * occupies, and an error/ok severity. A read-only view over the SAME decode — not a second
     * parser. Normal decode() is untouched (ranges are collected only here).
     * @param packet
     */
    public async dissect(packet: Buffer): Promise<DissectionLayer[]> {
        const codecData: CodecData = {packet: packet, startPos: 0, postHandlers: []}
        const codecModules: CodecModule[] = []
        await this.#decode(codecData, codecModules, true)
        const postDecodeHandlers: PostHandlerItem[] = ProcessPacketDecodePostHandlers(codecData.postHandlers)
        let postDecodeHandler: PostHandlerItem | undefined = postDecodeHandlers.shift()
        while (postDecodeHandler) {
            await postDecodeHandler.handler()
            postDecodeHandler = postDecodeHandlers.shift()
        }
        return codecModules.map((codecModule: CodecModule): DissectionLayer => {
            const schema: CodecSchema | undefined = this.#codecSchemas.find((codecSchema: CodecSchema): boolean => codecSchema.id === codecModule.id)
            const ranges: Map<string, FieldByteRange> = codecModule.getByteRanges() ? codecModule.getByteRanges()! : new Map()
            const errorPaths: Set<string> = new Set(codecModule.errors.map((e: CodecErrorInfo): string => e.path))
            return {
                id: codecModule.id,
                name: codecModule.name,
                errors: codecModule.errors,
                fields: this.#dissectFields(codecModule.instance.getValue(), schema ? (schema.schema as any) : undefined, '', ranges, errorPaths, packet)
            }
        })
    }

    /**
     * Recursively project a decoded value tree + its schema (for labels) + the collected byte ranges
     * into dissection fields. Scalar leaves carry their byte span; objects/arrays nest as children.
     * @private
     */
    #dissectFields(data: any, schema: any, pathPrefix: string, ranges: Map<string, FieldByteRange>, errorPaths: Set<string>, packet: Buffer): DissectionField[] {
        const fields: DissectionField[] = []
        if (data === null || typeof data !== 'object') return fields
        const properties: any = schema ? schema.properties : undefined
        for (const key of Object.keys(data)) {
            const node: any = properties ? properties[key] : undefined
            const value: any = data[key]
            const path: string = pathPrefix ? `${pathPrefix}.${key}` : key
            const range: FieldByteRange | undefined = ranges.get(path)
            const field: DissectionField = {name: key, severity: errorPaths.has(path) ? 'error' : 'ok'}
            if (node && node.label) field.label = node.label
            if (range) {
                field.offset = range.offset
                field.length = range.length
                field.rawBytes = packet.subarray(range.offset, range.offset + range.length).toString('hex')
            }
            if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
                field.children = this.#dissectFields(value, node, path, ranges, errorPaths, packet)
            } else if (Array.isArray(value)) {
                field.children = value.map((item: any, index: number): DissectionField => {
                    if (item !== null && typeof item === 'object') {
                        return {name: `${index}`, severity: 'ok', children: this.#dissectFields(item, node ? node.items : undefined, `${path}.${index}`, ranges, errorPaths, packet)}
                    }
                    return {name: `${index}`, severity: 'ok', value: item}
                })
            } else {
                field.value = value
            }
            fields.push(field)
        }
        return fields
    }

    /**
     * One-line human summary of a decoded packet (Wireshark's Info column). The innermost layer that
     * declares a `summary` template in its schema wins (the most specific layer describes the packet);
     * the template's ${dotted.field} placeholders are filled from that layer's decoded data. Falls back
     * to the innermost non-raw layer's name when no template is declared. Read-only projection.
     * @param decoded
     */
    public summary(decoded: CodecDecodeResult[]): string {
        for (let i: number = decoded.length - 1; i >= 0; i--) {
            const schema: ProtocolJSONSchema | undefined = this.#codecSchemas.find((codecSchema: CodecSchema): boolean => codecSchema.id === decoded[i].id)?.schema
            if (schema && schema.summary) return this.#renderSummary(schema.summary, decoded[i].data)
        }
        for (let i: number = decoded.length - 1; i >= 0; i--) {
            if (decoded[i].id !== this.#rawDataCodec.PROTOCOL_ID) return decoded[i].name
        }
        return decoded.length ? decoded[decoded.length - 1].name : ''
    }

    #renderSummary(template: string, data: any): string {
        return template.replace(/\$\{([^}]+)\}/g, (_match: string, path: string): string => {
            const value: any = path.split('.').reduce((object: any, key: string): any => (object == null ? undefined : object[key]), data)
            return value === undefined || value === null ? '' : String(value)
        })
    }
}
