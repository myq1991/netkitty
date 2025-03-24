import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {UInt16ToHex} from '../lib/NumberToHex'
import {CodecModule} from '../types/CodecModule'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {FixHexString} from '../lib/FixHexString'
import {BufferToUInt16, BufferToUInt8} from '../lib/BufferToNumber'
import {UInt16ToBuffer, UInt32ToBuffer, UInt8ToBuffer} from '../lib/NumberToBuffer'
import {BufferToHex} from '../lib/BufferToHex'
import {IPv4ToBuffer} from '../lib/IPToBuffer'
import {BufferToIPv4} from '../lib/BufferToIP'

export default class IPv4 extends BaseHeader {

    /**
     * Calculate IPv4 header checksum
     * @param headerBuffer
     * @protected
     */
    protected calculateIPv4Checksum(headerBuffer: Buffer): number {
        const header: Uint8Array = Uint8Array.from(headerBuffer)
        let sum: number = 0
        for (let i: number = 0; i < header.length; i += 2) {
            let word = (header[i] << 8) + (header[i + 1] || 0)
            sum += word
        }
        while (sum >>> 16) {
            sum = (sum & 0xFFFF) + (sum >>> 16)
        }
        return (~sum) & 0xFFFF
    }

    public SCHEMA: ProtocolJSONSchema = {
        properties: {
            version: {
                type: 'integer',
                label: 'Version',
                minimum: 0,
                maximum: 15,
                decode: (): void => {
                    this.instance.version.setValue(this.readBits(0, 1, 0, 4))
                    if (this.instance.version.getValue() !== 4) this.recordError(this.instance.version.getPath(), 'IPv4 version should be 4')
                },
                encode: (): void => {
                    let version: number = this.instance.version.getValue()
                    version = parseInt((version ? version : 4).toString())
                    version = version > 15 ? 15 : version
                    version = version < 0 ? 0 : version
                    if (version !== 4) this.recordError(this.instance.version.getPath(), 'IPv4 version should be 4')
                    this.writeBits(0, 1, 0, 4, version)
                }
            },
            hdrLen: {
                type: 'integer',
                label: 'Header Length',
                minimum: 20,
                maximum: 60,
                decode: (): void => {
                    this.instance.hdrLen.setValue(this.readBits(0, 1, 4, 4) * 4)
                },
                encode: (): void => {
                    let headerLength: number = this.instance.hdrLen.getValue()
                    if (!headerLength) headerLength = headerLength ? headerLength : 0
                    if (headerLength) headerLength = Math.floor(headerLength / 4)
                    this.writeBits(0, 1, 4, 4, headerLength)
                    if (!headerLength) this.addPostSelfEncodeHandler((): void => {
                        this.instance.hdrLen.setValue(this.length)
                        this.writeBits(0, 1, 4, 4, Math.floor(this.length / 4))
                    }, 10)
                }
            },
            dsfield: {
                type: 'object',
                label: 'Differentiated Services Field',
                properties: {
                    dscp: {
                        type: 'integer',
                        minimum: 0,
                        maximum: 63,
                        label: 'Differentiated Services Codepoint',
                        decode: (): void => {
                            this.instance.dsfield.dscp.setValue(this.readBits(1, 1, 0, 6))
                        },
                        encode: (): void => {
                            let dscp: number = this.instance.dsfield.dscp.getValue()
                            dscp = dscp ? dscp : 0
                            this.writeBits(1, 1, 0, 6, dscp)
                        }
                    },
                    ecn: {
                        type: 'integer',
                        label: 'Explicit Congestion Notification',
                        decode: (): void => {
                            this.instance.dsfield.ecn.setValue(this.readBits(1, 1, 6, 2))
                        },
                        encode: (): void => {
                            let ecn: number = this.instance.dsfield.ecn.getValue()
                            ecn = ecn ? ecn : 0
                            this.writeBits(1, 1, 6, 2, ecn)
                        }
                    }
                }
            },
            length: {
                type: 'integer',
                label: 'Total Length',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.length.setValue(BufferToUInt16(this.readBytes(2, 2)))
                },
                encode: (): void => {
                    //This field's real value needs down stream codec invoke recode to fill
                    let length: number = this.instance.length.getValue()
                    length = length ? length : 0
                    if (length) {
                        this.writeBytes(2, UInt16ToBuffer(length))
                    } else {
                        this.addPostPacketEncodeHandler((): void => {
                            let startCount: boolean = false
                            let totalLength: number = 0
                            this.codecModules.forEach((codecModule: CodecModule): void => {
                                if (codecModule === this) startCount = true
                                if (startCount) totalLength += codecModule.length
                            })
                            this.writeBytes(2, UInt16ToBuffer(totalLength))
                        })
                    }
                }
            },
            id: {
                type: 'integer',
                label: 'Identification',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.id.setValue(BufferToUInt16(this.readBytes(4, 2)))
                },
                encode: (): void => {
                    if (this.instance.id.isUndefined()) this.recordError(this.instance.id.getPath(), 'Not Found')
                    let id: number = this.instance.id.getValue()
                    this.writeBytes(4, UInt16ToBuffer(id ? id : 0))
                }
            },
            flags: {
                type: 'object',
                label: 'Flags',
                properties: {
                    rb: {
                        type: 'integer',
                        enum: [0, 1],
                        label: 'Reserved bit',
                        decode: (): void => {
                            this.instance.flags.rb.setValue(this.readBits(6, 1, 0, 1))
                        },
                        encode: (): void => {
                            let rb: number
                            if (this.instance.flags.rb.isUndefined()) {
                                this.recordError(this.instance.flags.rb.getPath(), 'Not Found')
                                rb = 0
                            } else {
                                rb = this.instance.flags.rb.getValue()
                                rb = parseInt(rb.toString())
                            }
                            this.writeBits(6, 1, 0, 1, rb)
                        }
                    },
                    df: {
                        type: 'integer',
                        enum: [0, 1],
                        label: 'Don\'t fragment',
                        decode: (): void => {
                            this.instance.flags.df.setValue(this.readBits(6, 1, 1, 1))
                        },
                        encode: (): void => {
                            let df: number
                            if (this.instance.flags.df.isUndefined()) {
                                this.recordError(this.instance.flags.df.getPath(), 'Not Found')
                                df = 1
                            } else {
                                df = this.instance.flags.df.getValue()
                                df = parseInt(df.toString())
                            }
                            this.writeBits(6, 1, 1, 1, df)
                        }
                    },
                    mf: {
                        type: 'integer',
                        enum: [0, 1],
                        label: 'More fragments',
                        decode: (): void => {
                            this.instance.flags.mf.setValue(this.readBits(6, 1, 2, 1))
                        },
                        encode: (): void => {
                            let mf: number
                            if (this.instance.flags.mf.isUndefined()) {
                                this.recordError(this.instance.flags.mf.getPath(), 'Not Found')
                                mf = 0
                            } else {
                                mf = this.instance.flags.mf.getValue()
                                mf = parseInt(mf.toString())
                            }
                            this.writeBits(6, 1, 2, 1, mf)
                        }
                    }
                }
            },
            fragOffset: {
                type: 'integer',
                minimum: 0,
                maximum: 8191,
                label: 'Fragment Offset',
                decode: (): void => {
                    this.instance.fragOffset.setValue(this.readBits(6, 2, 3, 13))
                },
                encode: (): void => {
                    if (this.instance.fragOffset.isUndefined()) this.recordError(this.instance.fragOffset.getPath(), 'Not Found')
                    let fragOffset: number = this.instance.fragOffset.getValue()
                    fragOffset = fragOffset ? fragOffset : 0
                    this.writeBits(6, 2, 3, 13, fragOffset)
                }
            },
            ttl: {
                type: 'integer',
                minimum: 0,
                maximum: 255,
                label: 'Time to Live',
                decode: (): void => {
                    this.instance.ttl.setValue(BufferToUInt8(this.readBytes(8, 1)))
                },
                encode: (): void => {
                    if (this.instance.ttl.isUndefined()) this.recordError(this.instance.ttl.getPath(), 'Not Found')
                    let ttl: number = this.instance.ttl.getValue()
                    this.writeBytes(8, UInt8ToBuffer(ttl ? ttl : 0))
                }
            },
            protocol: {
                type: 'integer',
                label: 'Protocol',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.protocol.setValue(BufferToUInt8(this.readBytes(9, 1)))
                },
                encode: (): void => {
                    if (this.instance.protocol.isUndefined()) this.recordError(this.instance.protocol.getPath(), 'Not Found')
                    let protocol: number = this.instance.protocol.getValue()
                    this.writeBytes(9, UInt8ToBuffer(protocol ? protocol : 0))
                }
            },
            checksum: {
                type: 'integer',
                label: 'Header Checksum',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.checksum.setValue(BufferToUInt16(this.readBytes(10, 2)))
                },
                encode: (): void => {
                    let checksum: number = !this.instance.checksum.isUndefined() ? this.instance.checksum.getValue() : 0
                    checksum = parseInt(checksum.toString())
                    checksum = checksum ? checksum : 0
                    checksum = checksum > 65535 ? 65535 : checksum
                    checksum = checksum < 0 ? 0 : checksum
                    if (checksum) {
                        this.writeBytes(10, UInt16ToBuffer(checksum))
                    } else {
                        this.writeBytes(10, Buffer.alloc(2, 0))
                        this.addPostPacketEncodeHandler((): void => {
                            this.writeBytes(10, UInt16ToBuffer(this.calculateIPv4Checksum(this.packet.subarray(this.startPos, this.endPos))))
                        }, 65535)
                    }
                }
            },
            sip: {
                type: 'string',
                label: 'Source Address',
                minLength: 7,
                maxLength: 15,
                contentEncoding: StringContentEncodingEnum.UTF8,
                decode: (): void => {
                    const sipBuffer: Buffer = this.readBytes(12, 4)
                    this.instance.sip.setValue(BufferToIPv4(sipBuffer))
                },
                encode: (): void => {
                    if (this.instance.sip.isUndefined()) {
                        this.recordError(this.instance.sip.getPath(), 'Not Found')
                        this.instance.sip.setValue('0.0.0.0')
                    }
                    const sipStr: string = this.instance.sip.getValue().toString()
                    this.writeBytes(12, IPv4ToBuffer(sipStr))
                }
            },
            dip: {
                type: 'string',
                minLength: 7,
                maxLength: 15,
                label: 'Destination Address',
                contentEncoding: StringContentEncodingEnum.UTF8,
                decode: (): void => {
                    const dipBuffer: Buffer = this.readBytes(16, 4)
                    this.instance.dip.setValue(BufferToIPv4(dipBuffer))
                },
                encode: (): void => {
                    if (this.instance.dip.isUndefined()) {
                        this.recordError(this.instance.dip.getPath(), 'Not Found')
                        this.instance.dip.setValue('0.0.0.0')
                    }
                    const dipStr: string = this.instance.dip.getValue()
                    this.writeBytes(16, IPv4ToBuffer(dipStr))
                }
            },
            options: {
                type: 'string',
                label: 'Options',
                minLength: 0,
                maxLength: 40,
                contentEncoding: StringContentEncodingEnum.HEX,
                decode: (): void => {
                    if (this.length < (this.instance.hdrLen.getValue())) {
                        this.instance.options.setValue(BufferToHex(this.readBytes(this.length, (this.instance.hdrLen.getValue()) - this.length)))
                    }
                },
                encode: (): void => {
                    if (!this.instance.options.isUndefined()) {
                        let optionsBuffer: Buffer = Buffer.from(FixHexString(this.instance.options.getValue()), 'hex')
                        if (optionsBuffer.length > 40) optionsBuffer = optionsBuffer.subarray(0, 40)
                        const estimateHdrLen: number = this.length + optionsBuffer.length
                        if (estimateHdrLen % 4) {
                            /**
                             * IPv4 Header should have a length that a multiple of 32 bits
                             * @see https://learningnetwork.cisco.com/s/question/0D53i00000Kt6hHCAR/padding-field-on-ipv4-header
                             */
                            optionsBuffer = Buffer.concat([optionsBuffer, Buffer.from([0x00])])
                        }
                        this.writeBytes(this.length, optionsBuffer)
                    }
                }
            }
        }
    }

    public id: string = 'ipv4'

    public name: string = 'Internet Protocol Version 4'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.etherType.getValue() === UInt16ToHex(0x0800)
    }
}
