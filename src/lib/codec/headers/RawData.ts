import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {BufferToHex} from '../lib/BufferToHex'

export class RawData extends BaseHeader {

    public readonly SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            data: {
                type: 'string',
                label: 'Raw',
                contentEncoding: StringContentEncodingEnum.HEX,
                decode: (): void => {
                    const dataLength: number = this.packet.length - this.startPos
                    this.instance.data.setValue(BufferToHex(this.readBytes(0, dataLength)))
                },
                encode: (): void => {
                    this.writeBytes(0, Buffer.from(this.instance.data.getValue().toString(), 'hex'))
                }
            }
        }
    }

    public readonly id: string = 'raw'

    public readonly name: string = 'Raw Data'

    public readonly nickname: string = 'Raw'

    public match(): boolean {
        return !!this.prevCodecModule
    }

}
