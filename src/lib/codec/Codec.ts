import path from 'node:path'
import {readdirSync} from 'fs'
import {CodecModuleConstructor} from './types/CodecModuleConstructor'
import {CodecModule} from './types/CodecModule'
import RawData from './headers/RawData'
import {CodecDecodeResult} from './types/CodecDecodeResult'
import {CodecEncodeInput} from './types/CodecEncodeInput'
import {CodecErrorInfo} from './types/CodecErrorInfo'
import {PostHandlerItem} from './types/PostHandlerItem'
import {CodecData} from './types/CodecData'
import {SortPostHandlers} from './lib/SortPostHandlers'
import {NoAvailableCodecError} from '../../errors/NoAvailableCodecError'
import {FlexibleObject} from './lib/FlexibleObject'
import {CodecSchema} from './types/CodecSchema'

const HEADER_CODECS_DIRECTORY: string = path.resolve(__dirname, './headers')

export class Codec {

    readonly #codecModuleConstructors: CodecModuleConstructor[] = []

    readonly #codecSchemas: CodecSchema[] = []

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
        let headerCodecs: CodecModuleConstructor[] = []
        readdirSync(HEADER_CODECS_DIRECTORY)
            .map((moduleName: string): string => path.resolve(HEADER_CODECS_DIRECTORY, moduleName))
            .map((codecModule: string): CodecModuleConstructor | null => {
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
            if (!codecModuleConstructor) continue
            const codecModule: CodecModule = codecModuleConstructor.CREATE_INSTANCE(codecData, codecModules)
            //TODO 可能需要加入验证
            codecModule.instance = new FlexibleObject(input.data)
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
        const codecModuleConstructor: CodecModuleConstructor | undefined = this.HEADER_CODECS.find((codecModuleConstructor: CodecModuleConstructor): boolean => codecModuleConstructor.MATCH(codecModules))
        //This unavailable error should not be thrown, the raw data codec will always match unknown data successfully
        if (!codecModuleConstructor) throw new NoAvailableCodecError('No available codec constructor')
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
        codecData.postHandlers = SortPostHandlers(codecData.postHandlers)
        let postDecodeHandler: PostHandlerItem | undefined = codecData.postHandlers.shift()
        while (postDecodeHandler) {
            await postDecodeHandler.handler()
            postDecodeHandler = codecData.postHandlers.shift()
        }
        return codecModules.map((codecModule: CodecModule): CodecDecodeResult => ({
            id: codecModule.id,
            name: codecModule.name,
            errors: codecModule.errors,
            data: codecModule.instance.getValue()
        }))
    }

    /**
     * Encode packet
     * @param inputs
     */
    public async encode(inputs: CodecEncodeInput[]): Promise<Buffer> {
        const errors: CodecErrorInfo[] = []
        const codecData: CodecData = await this.#encode(inputs, errors)
        codecData.postHandlers = SortPostHandlers(codecData.postHandlers)
        let postEncodeHandler: PostHandlerItem | undefined = codecData.postHandlers.shift()
        while (postEncodeHandler) {
            await postEncodeHandler.handler()
            postEncodeHandler = codecData.postHandlers.shift()
        }
        return codecData.packet
    }
}
