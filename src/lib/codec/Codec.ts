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
import * as packetHeaders from './PacketHeaders'

/**
 * Producer fields whose value decides the next layer, mirroring computeDemuxKeys: a layer whose
 * schema declares one of these can be followed by any codec registered under that demux namespace.
 */
const DEMUX_PRODUCERS: {field: string, namespace: string, numeric: boolean}[] = [
    {field: 'etherType', namespace: 'ethertype', numeric: false},
    {field: 'protocol', namespace: 'ipproto', numeric: true},
    {field: 'nxt', namespace: 'ipproto', numeric: true}
]

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
        for (const codecModuleConstructor of this.HEADER_CODECS) {
            if (codecModuleConstructor.PROTOCOL_ID === RawData.PROTOCOL_ID) {
                this.#rawDataCodec = codecModuleConstructor
                continue
            }
            const matchKeys: string[] = codecModuleConstructor.MATCH_KEYS
            if (matchKeys && matchKeys.length) {
                for (const matchKey of matchKeys) {
                    const bucket: CodecModuleConstructor[] | undefined = this.#dispatchTable.get(matchKey)
                    if (bucket) bucket.push(codecModuleConstructor)
                    else this.#dispatchTable.set(matchKey, [codecModuleConstructor])
                }
            } else {
                this.#heuristicCodecs.push(codecModuleConstructor)
            }
        }
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
        const instance: FlexibleObject = prevCodecModule.instance
        const keys: string[] = []
        const etherType: any = instance.etherType.getValue()
        if (etherType !== undefined && etherType !== null) keys.push(`ethertype:${etherType}`)
        const protocol: any = instance.protocol.getValue()
        if (protocol !== undefined && protocol !== null) keys.push(`ipproto:${protocol}`)
        const nextHeader: any = instance.nxt.getValue()
        if (nextHeader !== undefined && nextHeader !== null) keys.push(`ipproto:${nextHeader}`)
        return keys
    }

    /**
     * Select the codec for the next layer: dispatch table → content-heuristic
     * list → RawData. Never returns undefined; RawData always matches unknown
     * or malformed data, so decode cannot fail.
     * @param codecData
     * @param codecModules
     * @protected
     */
    protected selectCodec(codecData: CodecData, codecModules: CodecModule[]): CodecModuleConstructor {
        const prevCodecModule: CodecModule | undefined = codecModules[codecModules.length - 1]
        //1. Dispatch table: O(1) lookup by the previous layer's demux value.
        for (const matchKey of this.computeDemuxKeys(prevCodecModule)) {
            const bucket: CodecModuleConstructor[] | undefined = this.#dispatchTable.get(matchKey)
            if (!bucket) continue
            //A demux value maps to exactly one codec in practice: trust it directly,
            //which is what lets TCP over IPv6 (ipproto:6 via nxt) resolve correctly.
            if (bucket.length === 1) return bucket[0]
            //Ambiguous key (multiple registrants): confirm with each codec's match().
            for (const codecModuleConstructor of bucket) {
                if (codecModuleConstructor.MATCH(codecData, codecModules)) return codecModuleConstructor
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
            const codecModuleConstructor: CodecModuleConstructor | undefined = this.HEADER_CODECS.find((codec: CodecModuleConstructor): boolean => codec.PROTOCOL_ID === input.id)
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
    async #decode(codecData: CodecData, codecModules: CodecModule[] = []): Promise<void> {
        const codecModuleConstructor: CodecModuleConstructor = this.selectCodec(codecData, codecModules)
        const codecModule: CodecModule = codecModuleConstructor.CREATE_INSTANCE(codecData, codecModules)
        await codecModule.decode()
        codecData.startPos = codecModule.endPos
        codecModules.push(codecModule)
        if (codecData.startPos >= codecData.packet.length) return
        return this.#decode(codecData, codecModules)
    }

    /**
     * Decode packet
     * @param packet
     */
    public async decode(packet: Buffer): Promise<CodecDecodeResult[]> {
        const codecData: CodecData = {
            packet: packet,
            startPos: 0,
            postHandlers: []
        }
        const codecModules: CodecModule[] = []
        await this.#decode(codecData, codecModules)
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
    #producersOf(layerId: string): {field: string, namespace: string, numeric: boolean}[] {
        const schema: CodecSchema | undefined = this.#codecSchemas.find((codecSchema: CodecSchema): boolean => codecSchema.id === layerId)
        const properties: any = schema ? (schema.schema as any).properties : undefined
        if (!properties) return []
        return DEMUX_PRODUCERS.filter((producer: {field: string, namespace: string, numeric: boolean}): boolean => producer.field in properties)
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
                const value: string | number = producer.numeric ? Number(raw) : raw
                for (const codecModuleConstructor of constructors) {
                    const dedup: string = `${codecModuleConstructor.PROTOCOL_ID}@${producer.field}=${value}`
                    if (seen.has(dedup)) continue
                    seen.add(dedup)
                    result.push({id: codecModuleConstructor.PROTOCOL_ID, name: codecModuleConstructor.PROTOCOL_NAME, discriminator: {field: producer.field, value: value}})
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
            for (const producer of this.#producersOf(parent.id)) {
                const actual: any = (parent.data as any)[producer.field]
                if (actual === undefined || actual === null) continue
                const bucket: CodecModuleConstructor[] | undefined = this.#dispatchTable.get(`${producer.namespace}:${actual}`)
                if (bucket && bucket.some((codecModuleConstructor: CodecModuleConstructor): boolean => codecModuleConstructor.PROTOCOL_ID === child.id)) continue
                issues.push({
                    index: i,
                    parentId: parent.id,
                    childId: child.id,
                    field: producer.field,
                    actual: actual,
                    suggestion: this.childDiscriminator(parent.id, child.id),
                    message: `${parent.id}.${producer.field}=${actual} 与下一层 '${child.id}' 不符`
                })
            }
        }
        return issues
    }
}
