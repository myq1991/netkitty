import path from 'node:path'
import {readdirSync} from 'fs'
import {HeaderTreeNode} from './types/HeaderTreeNode'
import {CodecModuleConstructor} from './types/CodecModuleConstructor'
import {CodecModule} from './types/CodecModule'
import RawData from './headers/RawData'
import {CodecDecodeResult} from './types/CodecDecodeResult'
import {CodecEncodeInput} from './types/CodecEncodeInput'
import {CodecErrorInfo} from './types/CodecErrorInfo'
import {PostHandlerItem} from './types/PostHandlerItem'
import {CodecObject} from './types/CodecObject'

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
     * @param postEncodeHandlers
     * @private
     */
    async #encode(inputs: CodecEncodeInput[], errors: CodecErrorInfo[] = [], postEncodeHandlers: PostHandlerItem[] = []): Promise<Buffer> {
        // const codecObject: CodecObject = {
        //     packet: Buffer.from([]),
        //     startPos: 0
        // }
        let packet: Buffer = Buffer.from([])
        let startPos: number = 0
        const codecModules: CodecModule[] = []
        for (const input of inputs) {
            const codecModuleConstructor: CodecModuleConstructor | undefined = this.HEADER_CODECS.find((codec: CodecModuleConstructor): boolean => codec.PROTOCOL_ID === input.id)
            if (!codecModuleConstructor) continue
            const codecModule: CodecModule = codecModuleConstructor.CREATE_INSTANCE(packet, startPos, codecModules, postEncodeHandlers)
            codecModule.instance = input.data
            await codecModule.encode()
            codecModule.errors.forEach((errorInfo: CodecErrorInfo): number => errors.push(errorInfo))
            packet = codecModule.packet
            startPos = codecModule.endPos
            codecModules.push(codecModule)
        }
        return packet
    }

    /**
     * Internal decode packet
     * @param packet
     * @param codecModules
     * @param startPos
     * @param postDecodeHandlers
     * @private
     */
    async #decode(packet: Buffer, codecModules: CodecModule[] = [], startPos: number = 0, postDecodeHandlers: PostHandlerItem[] = []): Promise<void> {
        const codecModuleConstructor: CodecModuleConstructor | undefined = this.HEADER_CODECS.find((codecModuleConstructor: CodecModuleConstructor): boolean => codecModuleConstructor.MATCH(codecModules))
        if (!codecModuleConstructor) throw new Error('TODO 处理没有编解码器时的状况')
        const codecModule: CodecModule = codecModuleConstructor.CREATE_INSTANCE(packet, startPos, codecModules, postDecodeHandlers)
        await codecModule.decode()
        const nextStartPos: number = codecModule.endPos
        codecModules.push(codecModule)
        if (nextStartPos >= packet.length) return
        return this.#decode(packet, codecModules, nextStartPos, postDecodeHandlers)
    }

    /**
     * Decode packet
     * @param packet
     */
    public async decode(packet: Buffer): Promise<CodecDecodeResult[]> {

        const codecModules: CodecModule[] = []
        await this.#decode(packet, codecModules, 0, [])
        // const headerTree: HeaderTreeNode[] = codecModules.map((codecModule: CodecModule): HeaderTreeNode => codecModule.instance)
        //TODO post handler invoke
        return codecModules.map((codecModule: CodecModule): CodecDecodeResult => ({
            id: codecModule.id,
            name: codecModule.name,
            errors: codecModule.errors,
            data: codecModule.instance
        }))
    }

    /**
     * Encode packet
     * @param inputs
     */
    public async encode(inputs: CodecEncodeInput[]): Promise<Buffer> {
        return await this.#encode(inputs)
    }
}
