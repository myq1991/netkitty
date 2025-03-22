import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {CodecModule} from '../types/CodecModule'

export default class RawData extends BaseHeader {

    public readonly SCHEMA: ProtocolJSONSchema = {
        properties: {
            data: {
                type: 'array',
                items: {
                    type: 'number'
                },
                decode: (): void => {
                    const dataLength: number = this.packet.length - this.startPos
                    this.instance.data = Array.from(this.readBytes(0, dataLength))
                },
                encode: (): void => {
                    this.writeBytes(0, Buffer.from(this.instance.data as number[]))
                }
            }
        }
    }

    public readonly id: string = 'raw'

    public readonly name: string = 'Raw Data'

    public match(): boolean {
        return !!this.prevCodecModule
    }

}
