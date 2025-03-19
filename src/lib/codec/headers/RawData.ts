import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../lib/BaseHeader'
import {CodecModule} from '../types/CodecModule'

export default class RawData extends BaseHeader {

    public readonly SCHEMA: ProtocolJSONSchema = {
        properties: {
            data: {
                type: 'string',
                decode: () => {
                    const dataLength: number = this.packet.length - this.startPos
                    this.instance.data = this.readBytes(0, dataLength).toString('hex')
                },
                encode: () => {
                    //TODO
                }
            }
        }
    }

    public readonly id: string = 'raw'

    public readonly name: string = 'Raw Data'

    public match(prevCodecModule?: CodecModule): boolean {
        return !!prevCodecModule
    }

}
