import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {UInt16ToHex} from '../lib/NumberToHex'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {BufferToUInt16, BufferToUInt8} from '../lib/BufferToNumber'
import {UInt16ToBuffer, UInt8ToBuffer} from '../lib/NumberToBuffer'
import {BufferToIPv6} from '../lib/BufferToIP'
import {IPv6ToBuffer} from '../lib/IPToBuffer'
import {CodecModule} from '../types/CodecModule'

export class IPv6 extends BaseHeader {

    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            version: {
                type: 'integer',
                label: 'Version',
                minimum: 0,
                maximum: 15,
                decode: (): void => {
                    this.instance.version.setValue(this.readBits(0, 1, 0, 4))
                },
                encode: (): void => {
                    const version: number = this.instance.version.getValue(6, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.version.setValue(version)
                    this.writeBits(0, 1, 0, 4, version)
                }
            },
            tclass: {
                type: 'object',
                label: 'Traffic Class',
                properties: {
                    dscp: {
                        type: 'integer',
                        minimum: 0,
                        maximum: 63,
                        label: 'Differentiated Services Codepoint',
                        decode: (): void => {
                            this.instance.tclass.dscp.setValue(this.readBits(0, 4, 4, 6))
                        },
                        encode: (): void => {
                            const dscp: number = this.instance.tclass.dscp.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            this.instance.tclass.dscp.setValue(dscp)
                            this.writeBits(0, 4, 4, 6, dscp)
                        }
                    },
                    ecn: {
                        type: 'integer',
                        label: 'Explicit Congestion Notification',
                        minimum: 0,
                        maximum: 3,
                        decode: (): void => {
                            this.instance.tclass.ecn.setValue(this.readBits(0, 4, 10, 2))
                        },
                        encode: (): void => {
                            const ecn: number = this.instance.tclass.ecn.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            this.instance.tclass.ecn.setValue(ecn)
                            this.writeBits(0, 4, 10, 2, ecn)
                        }
                    }
                }
            },
            flow: {
                type: 'integer',
                label: 'Flow Label',
                minimum: 0,
                maximum: 1048575,
                decode: (): void => {
                    this.instance.flow.setValue(this.readBits(1, 3, 4, 20))
                },
                encode: (): void => {
                    const flow: number = this.instance.flow.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.flow.setValue(flow)
                    this.writeBits(1, 3, 4, 20, flow)
                }
            },
            plen: {
                type: 'integer',
                label: 'Payload Length',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.plen.setValue(BufferToUInt16(this.readBytes(4, 2)))
                },
                encode: (): void => {
                    const plen: number = this.instance.plen.getValue(0)
                    this.instance.plen.setValue(plen)
                    this.writeBytes(4, UInt16ToBuffer(plen))
                    if (!plen) {
                        this.addPostPacketEncodeHandler((): void => {
                            let startCount: boolean = false
                            let totalLength: number = 0
                            this.codecModules.forEach((codecModule: CodecModule): void => {
                                if (codecModule === this) startCount = true
                                if (startCount) totalLength += codecModule.length
                            })
                            let payloadLength: number = totalLength - 40
                            //The length is set to zero when a Hop-by-Hop extension header carries a Jumbo Payload option
                            if (payloadLength > 65535) payloadLength = 0
                            this.instance.plen.setValue(payloadLength)
                            this.writeBytes(4, UInt16ToBuffer(payloadLength))

                        })
                    }
                }
            },
            nxt: {
                type: 'integer',
                label: 'Next Header',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.nxt.setValue(BufferToUInt8(this.readBytes(6, 1)))
                },
                encode: (): void => {
                    const nxt: number = this.instance.nxt.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.nxt.setValue(nxt)
                    this.writeBytes(6, UInt8ToBuffer(nxt))
                }
            },
            hllm: {
                type: 'integer',
                label: 'Hop Limit',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.hllm.setValue(BufferToUInt8(this.readBytes(7, 1)))
                },
                encode: (): void => {
                    const hllm: number = this.instance.hllm.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.hllm.setValue(hllm)
                    this.writeBytes(7, UInt8ToBuffer(hllm))
                }
            },
            sip: {
                type: 'string',
                label: 'Source Address',
                contentEncoding: StringContentEncodingEnum.IPv6,
                decode: (): void => {
                    this.instance.sip.setValue(BufferToIPv6(this.readBytes(8, 16)))
                },
                encode: (): void => {
                    const sip: string = this.instance.sip.getValue('0000:0000:0000:0000:0000:0000:0000:0000', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.sip.setValue(sip)
                    this.writeBytes(8, IPv6ToBuffer(sip))
                }
            },
            dip: {
                type: 'string',
                label: 'Destination Address',
                contentEncoding: StringContentEncodingEnum.IPv6,
                decode: (): void => {
                    this.instance.dip.setValue(BufferToIPv6(this.readBytes(24, 16)))
                },
                encode: (): void => {
                    const dip: string = this.instance.dip.getValue('0000:0000:0000:0000:0000:0000:0000:0000', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.dip.setValue(dip)
                    this.writeBytes(24, IPv6ToBuffer(dip))
                }
            }
        }
    }

    public id: string = 'ipv6'

    public name: string = 'Internet Protocol Version 6'

    public nickname: string = 'IPv6'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.etherType.getValue() === UInt16ToHex(0x86dd)
    }

}
