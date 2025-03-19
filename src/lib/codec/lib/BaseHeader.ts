import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {HeaderTreeNode} from '../types/HeaderTreeNode'
import {CodecModule} from '../types/CodecModule'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'

export abstract class BaseHeader {

    protected static get CODEC_INSTANCE(): CodecModule {
        return new (this as any)()
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

    public static MATCH(prevCodecModule?: CodecModule): boolean {
        return this.CODEC_INSTANCE.match(prevCodecModule)
    }

    public static CREATE_INSTANCE(packet: Buffer, startPos: number): CodecModule {
        return new (this as any)(packet, startPos)
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
     * Header length
     * @protected
     */
    protected headerLength: number = 0

    constructor(packet: Buffer, startPos: number) {
        this.packet = packet
        this.startPos = startPos
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
     * @param prevCodecModule
     */
    public abstract match(prevCodecModule?: CodecModule): boolean

    /**
     * Read bytes from buffer
     * @param offset
     * @param length
     * @protected
     */
    protected readBytes(offset: number, length: number): Buffer {
        const packetOffset: number = this.getPacketOffset(offset)
        const readEndPos: number = packetOffset + length
        const headerLength: number = readEndPos - this.startPos
        this.headerLength = this.headerLength < headerLength ? headerLength : this.headerLength
        return this.packet.subarray(packetOffset, packetOffset + length)
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
        const headerLength: number = writeEndPos - this.startPos
        this.headerLength = this.headerLength < headerLength ? headerLength : this.headerLength
        if (this.packet.length < writeEndPos) this.packet = Buffer.concat([this.packet, Buffer.alloc(writeEndPos - this.packet.length, 0)])
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
        const buffer: Buffer = this.readBytes(offset, length)
        const bitString: string = parseInt(buffer.toString('hex'), 16).toString(2).padStart(length * 8, '0')
        return parseInt(bitString.substring(bitOffset, bitOffset + bitLength), 2)
    }

    protected writeBits(offset: number) {
        //TODO
    }

    /**
     * Get field codecs from schema tree
     * @param schema
     * @param codecName
     * @param codecs
     * @protected
     */
    protected getFieldCodecs(schema: ProtocolFieldJSONSchema, codecName: string, codecs: (() => Promise<void>)[] = []): (() => Promise<void>)[] {
        if (!schema.properties) return codecs
        for (const propertyName of Object.keys(schema.properties)) {
            const fieldSchema: ProtocolFieldJSONSchema = schema.properties[propertyName]
            const codec: (() => void | Promise<void>) | undefined = fieldSchema[codecName]
            if (!codec) continue
            codecs.push(async (): Promise<void> => await codec())
            if (fieldSchema.properties) this.getFieldCodecs(fieldSchema, codecName, codecs)
        }
        return codecs
    }

    /**
     * Decode packet header field by field
     */
    public async decode(): Promise<void> {
        const decodes: (() => Promise<void>)[] = this.getFieldCodecs(this.SCHEMA as ProtocolFieldJSONSchema, 'decode')
        for (const decode of decodes) {
            await decode()
        }
    }

    /**
     * Encode packet header field by field
     */
    public async encode(): Promise<void> {
        const encodes: (() => Promise<void>)[] = this.getFieldCodecs(this.SCHEMA as ProtocolFieldJSONSchema, 'encode')
        for (const encode of encodes) {
            await encode()
        }
    }
}
