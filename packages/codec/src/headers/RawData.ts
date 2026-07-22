import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {BufferToHex} from '../helper/BufferToHex'

/**
 * The forced catch-all header. The codec selects it as the final fallback when no
 * demux-table or content-heuristic codec matches, so decode never fails: any bytes
 * left unparsed at the current offset are captured verbatim into a single lower-case
 * hex `data` field and re-emitted byte-for-byte on encode. Not a protocol
 * (`isProtocol = false`); matches whenever there is a previous layer to trail.
 */
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

    public readonly isProtocol: boolean = false

    public match(): boolean {
        return !!this.prevCodecModule
    }

}
