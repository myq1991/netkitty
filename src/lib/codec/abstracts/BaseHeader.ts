import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {CodecModule} from '../types/CodecModule'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {CodecErrorInfo} from '../types/CodecErrorInfo'
import {PostHandlerItem} from '../types/PostHandlerItem'
import {SortPostHandlers} from '../lib/SortPostHandlers'
import {CodecData} from '../types/CodecData'
import {FlexibleObject} from '../lib/FlexibleObject'
import {Ajv, ErrorObject, ValidateFunction} from 'ajv'
import {HeaderTreeNode} from '../types/HeaderTreeNode'
import {CodecSchemaValidateError} from '../../../errors/CodecSchemaValidateError'
import {BufferToUInt8, BufferToUInt16, BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer, UInt32ToBuffer} from '../../helper/NumberToBuffer'

const CONSTRUCTOR_VALIDATE_KEY: string = '__validate'

//Per-codec-class cached MATCH probe. Content-heuristic selection calls MATCH() on many candidates
//per layer; each used to build a whole fresh instance (rebuilding the SCHEMA) just to run match().
//Since match() only inspects the previous layer and the raw buffer, one reusable probe per class
//suffices — see BaseHeader.MATCH / bindContext.
const MATCH_PROBE_KEY: string = '__matchProbe'

/** Absolute byte span a field occupies in the packet, collected during a dissect pass. */
export type FieldByteRange = {offset: number, length: number}

export abstract class BaseHeader {

    protected static get CODEC_INSTANCE(): CodecModule {
        return new (this as any)()
    }

    protected static CREATE_CODEC_INSTANCE_WITCH_CODEC_MODULES(codecData: CodecData, codecModules: CodecModule[]): CodecModule {
        return this.CREATE_INSTANCE(codecData, codecModules)
    }

    public static get PROTOCOL_ID(): string {
        return this.CODEC_INSTANCE.id
    }

    public static get PROTOCOL_NAME(): string {
        return this.CODEC_INSTANCE.name
    }

    /**
     * Demux keys this header registers in the codec dispatch table.
     * Empty (the default) means the header is matched by its content-heuristic
     * match() instead of by an upper-layer demultiplexing value.
     */
    public static get MATCH_KEYS(): string[] {
        return this.CODEC_INSTANCE.matchKeys
    }

    public static get PROTOCOL_SCHEMA(): ProtocolJSONSchema {
        const schema: ProtocolJSONSchema = JSON.parse(JSON.stringify(this.CODEC_INSTANCE.SCHEMA))
        if (!Object.hasOwn(this, CONSTRUCTOR_VALIDATE_KEY)) {
            const validate: ValidateFunction = new Ajv({
                strict: false,
                useDefaults: true,
                coerceTypes: true
            }).compile(schema)
            Object.defineProperty(this, CONSTRUCTOR_VALIDATE_KEY, {
                enumerable: false,
                configurable: false,
                value: validate
            })
        }
        return schema
    }

    public static MATCH(codecData: CodecData, codecModules: CodecModule[]): boolean {
        //Reuse one cached probe instance per codec class instead of rebuilding a full instance (and its
        //SCHEMA) for every candidate. match() only reads the previous layer and the raw buffer, never
        //this header's SCHEMA/instance, so rebinding context is enough. selectCodec runs synchronously,
        //so the shared probe never overlaps across concurrent decodes.
        let probe: any = Object.hasOwn(this, MATCH_PROBE_KEY) ? (this as any)[MATCH_PROBE_KEY] : undefined
        if (!probe) {
            probe = new (this as any)()
            Object.defineProperty(this, MATCH_PROBE_KEY, {enumerable: false, configurable: false, value: probe})
        }
        probe.bindContext(codecData, codecModules ? codecModules : [])
        return probe.match()
    }

    public static CREATE_INSTANCE(codecData: CodecData, codecModules: CodecModule[]): CodecModule {
        return new (this as any)(codecData, codecModules)
    }

    /**
     * Protocol schema definition
     */
    public readonly abstract SCHEMA: ProtocolJSONSchema

    /**
     * Program used header id
     */
    public readonly abstract id: string

    /**
     * Human-readable header name
     */
    public readonly abstract name: string

    /**
     * Human-readable header nickname
     */
    public readonly abstract nickname: string

    /**
     * Current header is a protocol or not
     */
    public readonly isProtocol: boolean = true

    /**
     * Upper-layer demultiplexing keys that select this header, e.g.
     * ['ethertype:0800'] or ['ipproto:6']. Registered in the codec dispatch
     * table for O(1) selection during decode. Leave empty for headers that
     * must inspect their own bytes to match (TLS, IEC104, tunnels); those fall
     * back to the content-heuristic match() list.
     */
    public readonly matchKeys: string[] = []

    /**
     * Encode/Decode error info objects
     */
    public errors: CodecErrorInfo[] = []

    /**
     * Header schema instance
     */
    public instance: FlexibleObject = new FlexibleObject()

    //Dissect-only instrumentation: when #byteRanges is non-null, each field read records the packet
    //span it covered (keyed by the field being decoded). Off (null) during normal decode/encode, so
    //the hot path is untouched. See enableByteRangeTracking() / getByteRanges().
    #byteRanges: Map<string, FieldByteRange> | null = null

    #currentFieldPath: string = ''

    /**
     * Turn on byte-range collection for a dissect pass (call before decode()). Additive and
     * read-only: it changes nothing about the decoded values, only records where each field lives.
     */
    public enableByteRangeTracking(): void {
        this.#byteRanges = new Map()
    }

    /** The byte span each field occupied, or null if this header was not dissected. */
    public getByteRanges(): Map<string, FieldByteRange> | null {
        return this.#byteRanges
    }

    /**
     * Entire packet buffer data getter
     */
    public get packet(): Buffer {
        return this.codecData.packet
    }

    /**
     * Entire packet buffer data setter
     * @param packet
     */
    public set packet(packet: Buffer) {
        this.codecData.packet = packet
    }

    /**
     * The start position of this header in the entire packet's buffer
     */
    public startPos: number = 0

    /**
     * The end position of this header in the entire packet's buffer
     */
    public get endPos(): number {
        return this.startPos + this.headerLength
    }

    /**
     * Readonly Header length
     */
    public get length(): number {
        return this.headerLength
    }

    /**
     * Header length
     * @protected
     */
    protected headerLength: number = 0

    /**
     * Previous Codec module
     * @protected
     */
    protected prevCodecModule!: CodecModule

    /**
     * Codec modules
     * @protected
     */
    protected codecModules!: CodecModule[]

    /**
     * Previous codec modules
     * @protected
     */
    protected prevCodecModules!: CodecModule[]

    /**
     * Current header index in packet headers
     * @protected
     */
    protected headerIndex: number = 0

    /**
     * Post packet handlers
     * @protected
     */
    protected get postPacketHandlers(): PostHandlerItem[] {
        if (this.codecData.postHandlers[this.headerIndex] === undefined) this.codecData.postHandlers[this.headerIndex] = []
        return this.codecData.postHandlers[this.headerIndex]
    }

    /**
     * Registered post encode handlers (CodecModule)
     * @protected
     */
    protected readonly postSelfEncodeHandlers: PostHandlerItem[] = []

    /**
     * Registered post decode handlers (CodecModule)
     * @protected
     */
    protected readonly postSelfDecodeHandlers: PostHandlerItem[] = []

    /**
     * Codec data
     * @protected
     */
    protected codecData!: CodecData

    constructor(codecData: CodecData, codecModules: CodecModule[]) {
        this.bindContext(codecData, codecModules)
    }

    /**
     * (Re)bind this instance's decode/match context. Extracted from the constructor so the static
     * MATCH probe can reuse a single cached instance across heuristic candidates instead of rebuilding
     * the whole SCHEMA for each — match() only reads the previous layer and the raw buffer.
     */
    protected bindContext(codecData: CodecData, codecModules: CodecModule[]): void {
        this.codecData = codecData
        this.startPos = codecData?.startPos ? codecData.startPos : 0
        codecModules = codecModules ? codecModules : []
        this.codecModules = codecModules
        this.prevCodecModules = [...codecModules]
        const prevCodecModuleIndex: number = this.prevCodecModules.length - 1
        this.prevCodecModule = this.prevCodecModules[prevCodecModuleIndex > -1 ? prevCodecModuleIndex : 0]
        this.headerIndex = this.prevCodecModules.length
    }

    /**
     * Get packet data offset
     * @param offset
     * @protected
     */
    protected getPacketOffset(offset: number): number {
        return this.startPos + offset
    }

    /**
     * Is data buffer fits current header codec
     */
    public abstract match(): boolean

    /**
     * Internal read bytes from buffer
     * @param offset
     * @param length
     * @param expandBufferLength
     * @param changeHeaderLength
     * @private
     */
    #readBytes(offset: number, length: number, expandBufferLength: boolean, changeHeaderLength: boolean): Buffer {
        const packetOffset: number = this.getPacketOffset(offset)
        let readEndPos: number = packetOffset + length
        if (this.packet.length < readEndPos) {
            if (expandBufferLength) {
                this.packet = Buffer.concat([this.packet, Buffer.alloc(readEndPos - this.packet.length, 0)])
            } else {
                readEndPos = this.packet.length
            }
        }
        const headerLength: number = readEndPos - this.startPos
        if (changeHeaderLength) this.headerLength = this.headerLength < headerLength ? headerLength : this.headerLength
        //Dissect instrumentation: attribute this read's absolute span to the field being decoded,
        //extending the field's range if it reads more than once (e.g. an address + its value).
        if (this.#byteRanges && this.#currentFieldPath) {
            const existing: FieldByteRange | undefined = this.#byteRanges.get(this.#currentFieldPath)
            if (existing) {
                const start: number = Math.min(existing.offset, packetOffset)
                const end: number = Math.max(existing.offset + existing.length, packetOffset + length)
                this.#byteRanges.set(this.#currentFieldPath, {offset: start, length: end - start})
            } else {
                this.#byteRanges.set(this.#currentFieldPath, {offset: packetOffset, length: length})
            }
        }
        return this.packet.subarray(packetOffset, packetOffset + length)
    }

    /**
     * Read bytes from buffer
     * @param offset
     * @param length
     * @param dryRun
     * @protected
     */
    protected readBytes(offset: number, length: number, dryRun: boolean = false): Buffer {
        return this.#readBytes(offset, length, false, !dryRun)
    }

    /**
     * Write bytes to buffer
     * @param offset
     * @param buffer
     * @protected
     */
    protected writeBytes(offset: number, buffer: Buffer): void {
        const packetOffset: number = this.getPacketOffset(offset)
        const writeEndPos: number = packetOffset + buffer.length
        this.#readBytes(offset, buffer.length, true, true)
        this.packet.fill(buffer, packetOffset, writeEndPos)
    }

    /**
     * Read bits from buffer
     * @param offset
     * @param length
     * @param bitOffset
     * @param bitLength
     * @protected
     */
    protected readBits(offset: number, length: number, bitOffset: number, bitLength: number): number {
        const buffer: Buffer = this.#readBytes(offset, length, false, true)
        //MSB-first bit extraction over a `length`-octet window. Available bytes occupy the low end;
        //missing (truncated) high bits read as 0.
        const shift: number = length * 8 - bitOffset - bitLength
        if (shift < 0) return 0
        if (length <= 4) {
            //A window of ≤4 octets (≤32 bits) fits a JS number exactly — skip BigInt boxing. Use
            //arithmetic (not <</>>, which are 32-bit-signed in JS) so 32-bit widths stay correct.
            let narrow: number = 0
            for (const byte of buffer) narrow = narrow * 256 + byte
            return Math.floor(narrow / 2 ** shift) % (2 ** bitLength)
        }
        //Wider windows (48/64-bit GOOSE/SV fields) keep full precision via BigInt.
        let value: bigint = 0n
        for (const byte of buffer) value = (value << 8n) | BigInt(byte)
        const mask: bigint = (1n << BigInt(bitLength)) - 1n
        return Number((value >> BigInt(shift)) & mask)
    }

    /**
     * Write bits to buffer
     * @param offset
     * @param length
     * @param bitOffset
     * @param bitLength
     * @param value
     * @protected
     */
    protected writeBits(offset: number, length: number, bitOffset: number, bitLength: number, value: number): void {
        const buffer: Buffer = this.#readBytes(offset, length, true, true)
        //Overlay `bitLength` bits of `value` at `bitOffset` (MSB-first) into the octet window. Only
        //the low `bitLength` bits of value are written (out-of-range values wrap, matching a
        //fixed-width field), and encode never crashes.
        const out: Buffer = Buffer.alloc(buffer.length)
        if (length <= 4) {
            //≤32-bit window: plain number arithmetic, no BigInt boxing. Split the window into the
            //untouched high part, the target field, and the low part, then reassemble — all via
            //multiply/divide/modulo to stay correct at 32-bit widths (JS bit-ops are 32-bit-signed).
            let current: number = 0
            for (const byte of buffer) current = current * 256 + byte
            const shift: number = buffer.length * 8 - bitOffset - bitLength
            const modulo: number = 2 ** bitLength
            const divisor: number = 2 ** shift
            const field: number = (((Math.trunc(Number(value)) || 0) % modulo) + modulo) % modulo
            const blockSize: number = modulo * divisor
            let written: number = Math.floor(current / blockSize) * blockSize + field * divisor + current % divisor
            for (let i: number = buffer.length - 1; i >= 0; i--) {
                out[i] = written % 256
                written = Math.floor(written / 256)
            }
            this.writeBytes(offset, out)
            return
        }
        //Wider windows keep exact via BigInt.
        let current: bigint = 0n
        for (const byte of buffer) current = (current << 8n) | BigInt(byte)
        const shift: bigint = BigInt(buffer.length * 8 - bitOffset - bitLength)
        const fieldMask: bigint = (1n << BigInt(bitLength)) - 1n
        const field: bigint = (BigInt(Math.trunc(Number(value)) || 0) & fieldMask) << shift
        const written: bigint = (current & ~(fieldMask << shift)) | field
        let v: bigint = written
        for (let i: number = buffer.length - 1; i >= 0; i--) {
            out[i] = Number(v & 0xFFn)
            v >>= 8n
        }
        this.writeBytes(offset, out)
    }

    // ===== Field building blocks =====
    // Declarative field factories: one call yields the whole {type,label,min,max,decode,encode}
    // schema field, generating the decode/encode twin from a single declaration so the byte offset
    // and width live in one place (not duplicated across two hand-mirrored closures — the source of
    // the historical decode≠encode bugs). Closures re-resolve this.instance[name] at run time because
    // encode swaps in a fresh instance. Irregular fields keep their hand-written closures (escape hatch).

    /**
     * An unsigned big-endian integer field of `byteLength` octets at `offset`. Decode reads it into
     * `name`; encode clamps to the field's range (recording an error, never throwing) and writes it —
     * byte-for-byte identical to the hand-written pattern it replaces.
     * @protected
     */
    protected fieldUInt(name: string, offset: number, byteLength: number, label: string): ProtocolFieldJSONSchema {
        const maximum: number = byteLength === 1 ? 255 : byteLength === 2 ? 65535 : 4294967295
        const read: (buffer: Buffer) => number = byteLength === 1 ? BufferToUInt8 : byteLength === 2 ? BufferToUInt16 : BufferToUInt32
        const write: (value: number) => Buffer = byteLength === 1 ? UInt8ToBuffer : byteLength === 2 ? UInt16ToBuffer : UInt32ToBuffer
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: maximum,
            decode: (): void => {
                (this.instance as any)[name].setValue(read(this.readBytes(offset, byteLength)))
            },
            encode: (): void => {
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > maximum) {
                    this.recordError(node.getPath(), `Maximum value is ${maximum}`)
                    value = maximum
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(offset, write(value))
            }
        }
    }

    /**
     * Get field codecs from schema tree
     * @param schema
     * @param codecName
     * @param execBeforeSubCodecs
     * @param codecs
     * @protected
     */
    protected getFieldCodecs(schema: ProtocolFieldJSONSchema, codecName: string, execBeforeSubCodecs: boolean, codecs: (() => void | Promise<void>)[] = [], paths: string[] | null = null, pathPrefix: string = ''): (() => void | Promise<void>)[] {
        if (!schema.properties) return codecs
        for (const propertyName of Object.keys(schema.properties)) {
            const fieldSchema: ProtocolFieldJSONSchema = schema.properties[propertyName]
            const codec: (() => void | Promise<void>) | undefined = fieldSchema[codecName]
            //Push the raw closure (no async double-wrap) and skip fields with no codec entirely, so
            //decode/encode call each synchronously and only await genuine Promises. When `paths` is
            //provided (dissect only) a dotted field path is collected in parallel; otherwise there is
            //zero extra cost on the hot path (no per-field object, no string concat).
            const path: string = paths ? (pathPrefix ? `${pathPrefix}.${propertyName}` : propertyName) : ''
            if (execBeforeSubCodecs && codec) {
                codecs.push(codec)
                if (paths) paths.push(path)
            }
            if (fieldSchema.properties) this.getFieldCodecs(fieldSchema, codecName, execBeforeSubCodecs, codecs, paths, path)
            if (!execBeforeSubCodecs && codec) {
                codecs.push(codec)
                if (paths) paths.push(path)
            }
        }
        return codecs
    }

    /**
     * Record encode/decode error
     * @param path
     * @param message
     * @protected
     */
    protected recordError(path: string, message: string): void {
        this.errors.push({
            id: this.id,
            path: path,
            message: message
        })
    }

    /**
     * Register post encode handler for current codec
     * @param handler
     * @param priority
     * @protected
     */
    protected addPostSelfEncodeHandler(handler: () => void | Promise<void>, priority: number = 0): void {
        this.postSelfEncodeHandlers.push({
            priority: priority,
            handler: handler
        })
    }

    /**
     * Register post decode handler for current codec
     * @param handler
     * @param priority
     * @protected
     */
    protected addPostSelfDecodeHandler(handler: () => void | Promise<void>, priority: number = 0): void {
        this.postSelfDecodeHandlers.push({
            priority: priority,
            handler: handler
        })
    }

    /**
     * Register post encode handler for packet
     * @description Registered handler call sequence: LIFO (Last In First Out)
     * @param handler
     * @param priority
     * @protected
     */
    protected addPostPacketEncodeHandler(handler: () => void | Promise<void>, priority: number = 0): void {
        this.postPacketHandlers.push({
            priority: priority,
            handler: handler
        })
    }

    /**
     * Register post decode handler for packet
     * @description Registered handler call sequence: FIFO (First In First Out)
     * @param handler
     * @param priority
     * @protected
     */
    protected addPostPacketDecodeHandler(handler: () => void | Promise<void>, priority: number = 0): void {
        this.postPacketHandlers.push({
            priority: priority,
            handler: handler
        })
    }

    /**
     * Validate input json node is valid
     * @param headerTreeNode
     */
    public validate(headerTreeNode: HeaderTreeNode): HeaderTreeNode {
        let validate: ValidateFunction = this.constructor[CONSTRUCTOR_VALIDATE_KEY]
        if (!validate) {
            validate = new Ajv({
                strict: false,
                useDefaults: true,
                coerceTypes: true
            }).compile(this.SCHEMA)
            this.constructor[CONSTRUCTOR_VALIDATE_KEY] = validate
        }
        const isValid: boolean = validate(headerTreeNode)
        if (!isValid) {
            let errorObject: ErrorObject | undefined | null
            if (validate.errors) errorObject = validate.errors[0]
            const errorMessage: string = errorObject?.message ? errorObject.message : 'Unknown Error'
            throw new CodecSchemaValidateError(errorMessage)
        }
        return headerTreeNode
    }

    /**
     * Decode packet header field by field
     */
    public async decode(): Promise<void> {
        const paths: string[] | null = this.#byteRanges ? [] : null
        const decodes: (() => void | Promise<void>)[] = this.getFieldCodecs(this.SCHEMA as ProtocolFieldJSONSchema, 'decode', true, [], paths)
        for (let i: number = 0; i < decodes.length; i++) {
            //Decode must never throw (error-accumulation contract): a truncated/corrupt packet can
            //make a field's byte read run past the buffer or hit an invalid value. Contain that to a
            //recorded error so the remaining fields and layers still decode best-effort.
            //Call synchronously and only await genuine Promises — the vast majority of field
            //closures are synchronous, so this avoids a promise allocation + scheduler turn per field.
            if (paths) this.#currentFieldPath = paths[i]
            try {
                const result: void | Promise<void> = decodes[i]()
                if (result && typeof (result as {then?: unknown}).then === 'function') await result
            } catch (e) {
                this.recordError('', `Decode error: ${(e as Error).message}`)
            }
        }
        //Post-handler reads (cross-field/cross-layer fixups) are not a single field's bytes — clear
        //the tracked path so they are not attributed to whichever field decoded last.
        this.#currentFieldPath = ''
        const postSelfDecodeHandlers: PostHandlerItem[] = SortPostHandlers(this.postSelfDecodeHandlers)
        let postDecodeHandler: PostHandlerItem | undefined = postSelfDecodeHandlers.shift()
        while (postDecodeHandler) {
            try {
                await postDecodeHandler.handler()
            } catch (e) {
                this.recordError('', `Decode error: ${(e as Error).message}`)
            }
            postDecodeHandler = postSelfDecodeHandlers.shift()
        }
    }

    /**
     * Encode packet header field by field
     */
    public async encode(): Promise<void> {
        const encodes: (() => void | Promise<void>)[] = this.getFieldCodecs(this.SCHEMA as ProtocolFieldJSONSchema, 'encode', false)
        for (const encode of encodes) {
            //Shape validation is the deliberate fast-fail at the encode entry point (Ajv, in
            //Codec.#encode); it runs before we get here. Past that, a field's encode closure must
            //not crash the whole encode on an edge-case value — contain it to a recorded error so
            //the packet still assembles best-effort (matches the decode contract).
            //Synchronous fast-path (see decode): only await a genuinely returned Promise.
            try {
                const result: void | Promise<void> = encode()
                if (result && typeof (result as {then?: unknown}).then === 'function') await result
            } catch (e) {
                this.recordError('', `Encode error: ${(e as Error).message}`)
            }
        }
        const postSelfEncodeHandlers: PostHandlerItem[] = SortPostHandlers(this.postSelfEncodeHandlers)
        let postEncodeHandler: PostHandlerItem | undefined = postSelfEncodeHandlers.shift()
        while (postEncodeHandler) {
            try {
                await postEncodeHandler.handler()
            } catch (e) {
                this.recordError('', `Encode error: ${(e as Error).message}`)
            }
            postEncodeHandler = postSelfEncodeHandlers.shift()
        }
    }
}
