import EventEmitter from 'events'
import path from 'node:path'
import {readdirSync} from 'fs'
import {BaseProtocol} from './lib/BaseProtocol'
import {DecodeResult} from '../schema/JSONSchemaProtocol'
import RawData from './protocols/RawData'

const PROTOCOL_DIR: string = path.resolve(__dirname, './protocols')

export class Coder<T extends typeof BaseProtocol> extends EventEmitter {

    protected protocolConstructorMap: Map<string, T> = new Map()

    constructor() {
        super()
        this.loadProtocols()
    }

    /**
     * Load protocol constructors
     * @protected
     */
    protected loadProtocols() {
        const modules: string[] = readdirSync(PROTOCOL_DIR)
        const protocolConstructors: T[] = modules.map((module: string): T | null => {
            try {
                const moduleConstructor: T = require(path.resolve(PROTOCOL_DIR, module)).default
                return moduleConstructor.PROTOCOL_NAME ? moduleConstructor : null
            } catch (e) {
                return null
            }
        }).filter((protocol: T | null): protocol is T => !!protocol)
        protocolConstructors.forEach(protocolConstructor => this.protocolConstructorMap.set(protocolConstructor.PROTOCOL_NAME, protocolConstructor))
        //Set raw data protocol for those data cannot find protocol to handle
        this.protocolConstructorMap.set('$RawData', RawData as any)
    }

    public async encode() {
        //TODO
    }

    public async decode(data: Buffer): Promise<DecodeResult[]> {
        const HeaderConstructor: any = this.protocolConstructorMap.get('Ethernet II')!
        return await new HeaderConstructor(this.protocolConstructorMap).schemaDecode(data)
    }

}
