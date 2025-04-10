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

const CONSTRUCTOR_VALIDATE_KEY: string = '__validate'

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
        return this.CREATE_CODEC_INSTANCE_WITCH_CODEC_MODULES(codecData, codecModules ? codecModules : []).match()
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
     * Encode/Decode error info objects
     */
    public errors: CodecErrorInfo[] = []

    /**
     * Header schema instance
     */
    public instance: FlexibleObject = new FlexibleObject()

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
    protected readonly prevCodecModule: CodecModule

    /**
     * Codec modules
     * @protected
     */
    protected readonly codecModules: CodecModule[]

    /**
     * Previous codec modules
     * @protected
     */
    protected readonly prevCodecModules: CodecModule[]

    /**
     * Current header index in packet headers
     * @protected
     */
    protected readonly headerIndex: number = 0

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
    protected readonly codecData: CodecData

    constructor(codecData: CodecData, codecModules: CodecModule[]) {
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
        const bitString: string = parseInt(buffer.toString('hex'), 16).toString(2).padStart(length * 8, '0')
        return parseInt(bitString.substring(bitOffset, bitOffset + bitLength), 2)
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
        let bitArray: string[] = Array.from(parseInt(buffer.toString('hex'), 16).toString(2).padStart(buffer.length * 8, '0'))
        const valueBitArray: string[] = Array.from(value.toString(2).padStart(bitLength, '0'))
        bitArray = bitArray.map((bit: string, index: number): string => {
            if (index < bitOffset) return bit
            if (index >= (bitOffset + bitLength)) return bit
            return valueBitArray[index - bitOffset]
        })
        this.writeBytes(offset, Buffer.from(parseInt(bitArray.join(''), 2).toString(16).padStart(buffer.length * 2, '0'), 'hex'))
    }

    /**
     * Get field codecs from schema tree
     * @param schema
     * @param codecName
     * @param execBeforeSubCodecs
     * @param codecs
     * @protected
     */
    protected getFieldCodecs(schema: ProtocolFieldJSONSchema, codecName: string, execBeforeSubCodecs: boolean, codecs: (() => Promise<void>)[] = []): (() => Promise<void>)[] {
        if (!schema.properties) return codecs
        for (const propertyName of Object.keys(schema.properties)) {
            const fieldSchema: ProtocolFieldJSONSchema = schema.properties[propertyName]
            let codec: (() => void | Promise<void>) | undefined = fieldSchema[codecName]
            if (!codec) codec = async (): Promise<void> => (void (0))
            if (execBeforeSubCodecs) codecs.push(async (): Promise<void> => await codec())
            if (fieldSchema.properties) this.getFieldCodecs(fieldSchema, codecName, execBeforeSubCodecs, codecs)
            if (!execBeforeSubCodecs) codecs.push(async (): Promise<void> => await codec())
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
        const decodes: (() => Promise<void>)[] = this.getFieldCodecs(this.SCHEMA as ProtocolFieldJSONSchema, 'decode', true)
        for (const decode of decodes) {
            await decode()
        }
        const postSelfDecodeHandlers: PostHandlerItem[] = SortPostHandlers(this.postSelfDecodeHandlers)
        let postDecodeHandler: PostHandlerItem | undefined = postSelfDecodeHandlers.shift()
        while (postDecodeHandler) {
            await postDecodeHandler.handler()
            postDecodeHandler = postSelfDecodeHandlers.shift()
        }
    }

    /**
     * Encode packet header field by field
     */
    public async encode(): Promise<void> {
        const encodes: (() => Promise<void>)[] = this.getFieldCodecs(this.SCHEMA as ProtocolFieldJSONSchema, 'encode', false)
        for (const encode of encodes) {
            await encode()
        }
        const postSelfEncodeHandlers: PostHandlerItem[] = SortPostHandlers(this.postSelfEncodeHandlers)
        let postEncodeHandler: PostHandlerItem | undefined = postSelfEncodeHandlers.shift()
        while (postEncodeHandler) {
            await postEncodeHandler.handler()
            postEncodeHandler = postSelfEncodeHandlers.shift()
        }
    }
}
