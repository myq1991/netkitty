import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../lib/BaseHeader'
import {CodecModule} from '../types/CodecModule'

export default class RawData extends BaseHeader {

    public readonly SCHEMA: ProtocolJSONSchema = {
        properties: {
            data: {
                type: 'string',
                decode: (): void => {
                    const dataLength: number = this.packet.length - this.startPos
                    this.instance.data = this.readBytes(0, dataLength).toString('hex')
                },
                encode: (): void => {
                    this.writeBytes(0, Buffer.from(this.instance.data.toString(), 'hex'))
                }
            }
        }
    }

    public readonly id: string = 'raw'

    public readonly name: string = 'Raw Data'

    public match(prevCodecModule: CodecModule): boolean {
        return !!prevCodecModule
    }

}
