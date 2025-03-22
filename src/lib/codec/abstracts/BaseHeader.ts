import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {HeaderTreeNode} from '../types/HeaderTreeNode'
import {CodecModule} from '../types/CodecModule'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {CodecErrorInfo} from '../types/CodecErrorInfo'

export abstract class BaseHeader {

    protected static get CODEC_INSTANCE(): CodecModule {
        return new (this as any)()
    }

    protected static CREATE_CODEC_INSTANCE_WITCH_CODEC_MODULES(prevCodecModules: CodecModule[]): CodecModule {
        return new (this as any)(undefined, undefined, prevCodecModules)
    }

    public static get PROTOCOL_ID(): string {
        return this.CODEC_INSTANCE.id
    }

    public static get PROTOCOL_NAME(): string {
        return this.CODEC_INSTANCE.name
    }

    public static get PROTOCOL_SCHEMA(): ProtocolJSONSchema {
        return JSON.parse(JSON.stringify(this.CODEC_INSTANCE.SCHEMA))
    }

    public static MATCH(prevCodecModules: CodecModule[]): boolean {
        return this.CREATE_CODEC_INSTANCE_WITCH_CODEC_MODULES(prevCodecModules ? prevCodecModules : []).match()
    }

    public static CREATE_INSTANCE(packet: Buffer, startPos: number, prevCodecModules: CodecModule[]): CodecModule {
        return new (this as any)(packet, startPos, prevCodecModules)
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
     * Encode/Decode error info objects
     */
    public errors: CodecErrorInfo[] = []

    /**
     * Header schema instance
     */
    public instance: HeaderTreeNode = {}

    /**
     * Entire packet buffer data
     */
    public packet: Buffer = Buffer.from([])

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
     * Previous Codec modules
     * @protected
     */
    protected readonly prevCodecModules: CodecModule[]

    /**
     * Registered after encode handlers
     * @protected
     */
    protected readonly afterEncodeHandlers: (() => void | Promise<void>)[] = []

    /**
     * Registered after decode handlers
     * @protected
     */
    protected readonly afterDecodeHandlers: (() => void | Promise<void>)[] = []

    constructor(packet: Buffer, startPos: number, prevCodecModules: CodecModule[]) {
        this.packet = packet
        this.startPos = startPos
        prevCodecModules = prevCodecModules ? prevCodecModules : []
        this.prevCodecModules = prevCodecModules
        const prevCodecModuleIndex: number = this.prevCodecModules.length - 1
        this.prevCodecModule = this.prevCodecModules[prevCodecModuleIndex > -1 ? prevCodecModuleIndex : 0]
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
     * @private
     */
    #readBytes(offset: number, length: number, expandBufferLength: boolean): Buffer {
        const packetOffset: number = this.getPacketOffset(offset)
        const readEndPos: number = packetOffset + length
        if (this.packet.length < readEndPos && expandBufferLength) this.packet = Buffer.concat([this.packet, Buffer.alloc(readEndPos - this.packet.length, 0)])
        const headerLength: number = readEndPos - this.startPos
        this.headerLength = this.headerLength < headerLength ? headerLength : this.headerLength
        return this.packet.subarray(packetOffset, packetOffset + length)
    }

    /**
     * Read bytes from buffer
     * @param offset
     * @param length
     * @protected
     */
    protected readBytes(offset: number, length: number): Buffer {
        return this.#readBytes(offset, length, false)
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
        this.#readBytes(offset, buffer.length, true)
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
        const buffer: Buffer = this.#readBytes(offset, length, false)
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
        const buffer: Buffer = this.#readBytes(offset, length, true)
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
     * Register after encode handler
     * @param handler
     * @protected
     */
    protected afterEncode(handler: () => void | Promise<void>): void {
        this.afterEncodeHandlers.push(handler)
    }

    /**
     * Register after decode handler
     * @param handler
     * @protected
     */
    protected afterDecode(handler: () => void | Promise<void>): void {
        this.afterDecodeHandlers.push(handler)
    }

    /**
     * Set instance's node value
     * @param node
     * @param fields
     * @param value
     * @protected
     */
    protected setNodeValue(node: HeaderTreeNode, fields: string[], value: any): HeaderTreeNode {
        const field: string = fields.shift() as any
        if (fields.length) {
            node[field] = node[field] ? node[field] : {}
            return this.setNodeValue(node[field] as HeaderTreeNode, fields, value)
        } else {
            node[field] = value
            return node
        }
    }

    /**
     * Recode specific field AFTER entire header encoded
     * @param fieldPath
     * @param fieldValue
     * @param throwErrorIfNotFound
     */
    public async recodeField(fieldPath: string, fieldValue: any, throwErrorIfNotFound: boolean = false): Promise<void> {
        const fields: string[] = fieldPath.split('.')
        let fieldSchema: ProtocolFieldJSONSchema | null = this.SCHEMA as ProtocolFieldJSONSchema
        for (const field of fields) {
            if (!fieldSchema) break
            if (!fieldSchema.properties) break
            fieldSchema = !fieldSchema.properties[field] ? null : fieldSchema.properties[field]
        }
        if (!fieldSchema || !fieldSchema['encode']) {
            if (throwErrorIfNotFound) throw new Error('Encoder not found')
            return
        }
        this.instance = this.setNodeValue(this.instance, fields, fieldValue)
        const fieldEncoder: () => void | Promise<void> = fieldSchema['encode']
        await fieldEncoder()
    }

    /**
     * Decode packet header field by field
     */
    public async decode(): Promise<void> {
        const decodes: (() => Promise<void>)[] = this.getFieldCodecs(this.SCHEMA as ProtocolFieldJSONSchema, 'decode', true)
        for (const decode of decodes) {
            await decode()
        }
        let afterDecodeHandler: (() => void | Promise<void>) | undefined = this.afterDecodeHandlers.shift()
        while (afterDecodeHandler) {
            await afterDecodeHandler()
            afterDecodeHandler = this.afterDecodeHandlers.shift()
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
        let afterEncodeHandler: (() => void | Promise<void>) | undefined = this.afterEncodeHandlers.shift()
        while (afterEncodeHandler) {
            await afterEncodeHandler()
            afterEncodeHandler = this.afterEncodeHandlers.shift()
        }
    }
}
