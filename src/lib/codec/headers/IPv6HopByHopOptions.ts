import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {UInt16ToHex} from '../lib/NumberToHex'
import {BufferToUInt8} from '../lib/BufferToNumber'
import {UInt8ToBuffer} from '../lib/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

export class IPv6HopByHopOptions extends BaseHeader {

    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            nxt: {
                type: 'integer',
                label: 'Next Header',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.nxt.setValue(BufferToUInt8(this.readBytes(0, 1)))
                },
                encode: (): void => {
                    const nxt: number = this.instance.nxt.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.nxt.setValue(nxt)
                    this.writeBytes(0, UInt8ToBuffer(nxt))
                }
            },
            len: {
                type: 'integer',
                label: 'Length',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            items: {
                type: 'array',
                label: 'Option Items',
                items: {
                    anyOf: [
                        //Pad1
                        //PadN
                        //Tunnel Encapsulation Limit
                        //Router Alert
                        //CALIPSO
                        //SMF_DPD
                        //MPL Option
                        //ILNP Nonce
                        //Line-Identification Option
                        //IPv6 DFF Header
                        //Endpoint Identification
                        //Default
                        {
                            type: 'object',
                            label: 'Default',
                            properties: {
                                type: {
                                    type: 'integer',
                                    label: 'Type'
                                },
                                data: {
                                    type: 'string',
                                    label: 'Data',
                                    contentEncoding: StringContentEncodingEnum.HEX
                                }
                            }
                        }
                    ]
                },
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            }
        }
    }

    public id: string = 'ipv6-hopopt'

    public name: string = 'IPv6 Hop-by-Hop Option'

    public nickname: string = 'HopOpt'

    public readonly isProtocol: boolean = false

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.nxt.getValue() === UInt16ToHex(0x00)
    }

}
