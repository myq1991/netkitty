import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../lib/BaseHeader'
import {CodecModule} from '../types/CodecModule'

export default class Goose extends BaseHeader {
    public SCHEMA: ProtocolJSONSchema
    public id: string = 'goose'
    public name: string = 'GOOSE'

    public match(prevCodecModule: CodecModule, prevCodecModules: CodecModule[]): boolean {
        if (!prevCodecModule) return false
        return prevCodecModule.instance.etherType === '0x88b8'
    }
}
