import path from 'node:path'
import {readdirSync} from 'fs'
import {HeaderTreeNode} from './types/HeaderTreeNode'
import {CodecModuleConstructor} from './types/CodecModuleConstructor'
import {CodecModule} from './types/CodecModule'
import RawData from './headers/RawData'
import {CodecDecodeResult} from './types/CodecDecodeResult'

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

    async #encode() {
        //TODO
    }

    /**
     * Internal decode packet
     * @param packet
     * @param prevCodecModule
     * @param startPos
     * @param headerTree
     * @private
     */
    async #decode(packet: Buffer, prevCodecModule?: CodecModule, startPos: number = 0, headerTree: HeaderTreeNode[] = []): Promise<HeaderTreeNode[]> {
        const codecModuleConstructor: CodecModuleConstructor | undefined = this.HEADER_CODECS.find((codecModuleConstructor: CodecModuleConstructor): boolean => codecModuleConstructor.MATCH(prevCodecModule))
        if (!codecModuleConstructor) throw new Error('TODO 处理没有编解码器时的状况')
        const codecModule: CodecModule = codecModuleConstructor.CREATE_INSTANCE(packet, startPos)
        await codecModule.decode()
        const headerTreeNode: HeaderTreeNode = codecModule.instance
        this.defineHiddenProperty('id', codecModule.id, headerTreeNode)
        this.defineHiddenProperty('name', codecModule.name, headerTreeNode)
        headerTree.push(headerTreeNode)
        const nextStartPos: number = codecModule.endPos
        if (nextStartPos >= packet.length) return headerTree
        return this.#decode(packet, codecModule, nextStartPos, headerTree)
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
                data: headerTreeNode
            }
        })
    }
}
