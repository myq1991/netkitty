import path from 'node:path'
import {readdirSync} from 'fs'
import {HeaderTreeNode} from './types/HeaderTreeNode'
import {CodecModuleConstructor} from './types/CodecModuleConstructor'
import {CodecModule} from './types/CodecModule'
import RawData from './headers/RawData'
import {CodecDecodeResult} from './types/CodecDecodeResult'
import {CodecEncodeInput} from './types/CodecEncodeInput'
import {CodecErrorInfo} from './types/CodecErrorInfo'

const HEADER_CODECS_DIRECTORY: string = path.resolve(__dirname, './headers')

export class Codec {

    protected readonly HEADER_CODECS: CodecModuleConstructor[] = []

    constructor() {
        this.HEADER_CODECS = this.loadHeaderCodecs()
    }

    /**
     * Load header codecs
     * @protected
     */
    protected loadHeaderCodecs(): CodecModuleConstructor[] {
        let headerCodecs: CodecModuleConstructor[] = []
        readdirSync(HEADER_CODECS_DIRECTORY)
            .map((moduleName: string): string => path.resolve(HEADER_CODECS_DIRECTORY, moduleName))
            .map((codecModule: string) => {
                try {
                    const codecModuleConstructor: CodecModuleConstructor = require(codecModule).default
                    return codecModuleConstructor.PROTOCOL_NAME ? codecModuleConstructor : null
                } catch (e) {
                    return null
                }
            })
            .filter((codecModuleConstructor: CodecModuleConstructor | null): codecModuleConstructor is CodecModuleConstructor => !!codecModuleConstructor)
            .forEach((codecModuleConstructor: CodecModuleConstructor): number => headerCodecs.push(codecModuleConstructor))
        headerCodecs = headerCodecs.filter((codec: CodecModuleConstructor): boolean => codec.PROTOCOL_ID !== RawData.PROTOCOL_ID)
        //Ensure RawData codec is in the end of header codecs
        headerCodecs.push(RawData)
        return headerCodecs
    }

    /**
     * Generate hidden property key
     * @param key
     * @protected
     */
    protected generateHiddenPropertyKey(key: string): string {
        return `__$HIDDEN__${key}`
    }

    /**
     * Define hidden property key
     * @param key
     * @param value
     * @param target
     * @protected
     */
    protected defineHiddenProperty(key: string, value: any, target: Object): void {
        Object.defineProperty(target, this.generateHiddenPropertyKey(key), {
            configurable: false,
            enumerable: false,
            value: value
        })
    }

    /**
     * Get hidden property key
     * @param key
     * @param target
     * @protected
     */
    protected getHiddenProperty(key: string, target: Object): any {
        return Object.getOwnPropertyDescriptor(target, this.generateHiddenPropertyKey(key))?.value
    }

    /**
     * Internal encode headers to packet
     * @param inputs
     * @param errors
     * @private
     */
    async #encode(inputs: CodecEncodeInput[], errors: CodecErrorInfo[] = []): Promise<Buffer> {
        let packet: Buffer = Buffer.from([])
        let startPos: number = 0
        const prevCodecModules: CodecModule[] = []
        for (const input of inputs) {
            const codecModuleConstructor: CodecModuleConstructor | undefined = this.HEADER_CODECS.find((codec: CodecModuleConstructor): boolean => codec.PROTOCOL_ID === input.id)
            if (!codecModuleConstructor) continue
            const codecModule: CodecModule = codecModuleConstructor.CREATE_INSTANCE(packet, startPos, prevCodecModules)
            codecModule.instance = input.data
            await codecModule.encode()
            codecModule.errors.forEach((errorInfo: CodecErrorInfo): number => errors.push(errorInfo))
            packet = codecModule.packet
            startPos = codecModule.endPos
            prevCodecModules.push(codecModule)
        }
        return packet
    }

    /**
     * Internal decode packet
     * @param packet
     * @param prevCodecModules
     * @param startPos
     * @param headerTree
     * @private
     */
    async #decode(packet: Buffer, prevCodecModules: CodecModule[] = [], startPos: number = 0, headerTree: HeaderTreeNode[] = []): Promise<HeaderTreeNode[]> {
        const codecModuleConstructor: CodecModuleConstructor | undefined = this.HEADER_CODECS.find((codecModuleConstructor: CodecModuleConstructor): boolean => codecModuleConstructor.MATCH(prevCodecModules))
        if (!codecModuleConstructor) throw new Error('TODO 处理没有编解码器时的状况')
        const codecModule: CodecModule = codecModuleConstructor.CREATE_INSTANCE(packet, startPos, prevCodecModules)
        await codecModule.decode()
        const headerTreeNode: HeaderTreeNode = codecModule.instance
        this.defineHiddenProperty('id', codecModule.id, headerTreeNode)
        this.defineHiddenProperty('name', codecModule.name, headerTreeNode)
        this.defineHiddenProperty('errors', codecModule.errors, headerTreeNode)
        headerTree.push(headerTreeNode)
        const nextStartPos: number = codecModule.endPos
        if (nextStartPos >= packet.length) return headerTree
        prevCodecModules.push(codecModule)
        return this.#decode(packet, prevCodecModules, nextStartPos, headerTree)
    }

    /**
     * Decode packet
     * @param packet
     */
    public async decode(packet: Buffer): Promise<CodecDecodeResult[]> {
        const headerTree: HeaderTreeNode[] = await this.#decode(packet)
        return headerTree.map((headerTreeNode: HeaderTreeNode): CodecDecodeResult => {
            return {
                id: this.getHiddenProperty('id', headerTreeNode),
                name: this.getHiddenProperty('name', headerTreeNode),
                errors: this.getHiddenProperty('errors', headerTreeNode),
                data: headerTreeNode
            }
        })
    }

    /**
     * Encode packet
     * @param inputs
     */
    public async encode(inputs: CodecEncodeInput[]): Promise<Buffer> {
        return await this.#encode(inputs)
    }
}
