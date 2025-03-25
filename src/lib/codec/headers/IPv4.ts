import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {UInt16ToHex} from '../lib/NumberToHex'
import {CodecModule} from '../types/CodecModule'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {FixHexString} from '../lib/FixHexString'
import {BufferToUInt16, BufferToUInt8} from '../lib/BufferToNumber'
import {UInt16ToBuffer, UInt8ToBuffer} from '../lib/NumberToBuffer'
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
        type: 'object',
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
                    let version: number = this.instance.version.getValue(4)
                    version = version > 15 ? 15 : version
                    version = version < 0 ? 0 : version
                    if (version !== 4) this.recordError(this.instance.version.getPath(), 'IPv4 version should be 4')
                    this.instance.version.setValue(version)
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
                    let headerLength: number = this.instance.hdrLen.getValue(0)
                    if (headerLength) headerLength = headerLength ? Math.floor(headerLength / 4) : 0
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
                            const dscp: number = this.instance.dsfield.dscp.getValue(0)
                            this.instance.dsfield.dscp.setValue(dscp)
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
                            const ecn: number = this.instance.dsfield.ecn.getValue(0)
                            this.instance.dsfield.ecn.setValue(ecn)
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
                    let length: number = this.instance.length.getValue(0)
                    if (length) {
                        this.writeBytes(2, UInt16ToBuffer(length))
                    } else {
                        this.writeBytes(2, UInt16ToBuffer(length))
                        this.addPostPacketEncodeHandler((): void => {
                            let startCount: boolean = false
                            let totalLength: number = 0
                            this.codecModules.forEach((codecModule: CodecModule): void => {
                                if (codecModule === this) startCount = true
                                if (startCount) totalLength += codecModule.length
                            })
                            this.instance.length.setValue(totalLength)
                            this.writeBytes(2, UInt16ToBuffer(totalLength))
                        }, 1)
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
                    const id: number = this.instance.id.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.id.setValue(id)
                    this.writeBytes(4, UInt16ToBuffer(id))
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
                            const rb: number = this.instance.flags.rb.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            this.instance.flags.rb.setValue(rb)
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
                            const df: number = this.instance.flags.df.getValue(1, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            this.instance.flags.df.setValue(df)
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
                            const mf: number = this.instance.flags.mf.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            this.instance.flags.mf.setValue(mf)
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
                    const fragOffset: number = this.instance.fragOffset.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.fragOffset.setValue(fragOffset)
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
                    const ttl: number = this.instance.ttl.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.ttl.setValue(ttl)
                    this.writeBytes(8, UInt8ToBuffer(ttl))
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
                    const protocol: number = this.instance.protocol.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.protocol.setValue(protocol)
                    this.writeBytes(9, UInt8ToBuffer(protocol))
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
                    let checksum: number = this.instance.checksum.getValue(0)
                    checksum = checksum > 65535 ? 65535 : checksum
                    checksum = checksum < 0 ? 0 : checksum
                    if (checksum) {
                        this.instance.checksum.setValue(checksum)
                        this.writeBytes(10, UInt16ToBuffer(checksum))
                    } else {
                        this.instance.checksum.setValue(checksum)
                        this.writeBytes(10, UInt16ToBuffer(checksum))
                        this.addPostPacketEncodeHandler((): void => {
                            const calcChecksum: number = this.calculateIPv4Checksum(this.packet.subarray(this.startPos, this.endPos))
                            this.instance.checksum.setValue(calcChecksum)
                            this.writeBytes(10, UInt16ToBuffer(calcChecksum))
                        }, 2)
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
                    const sipStr: string = this.instance.sip.getValue('0.0.0.0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.sip.setValue(sipStr)
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
                    const dipStr: string = this.instance.dip.getValue('0.0.0.0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.dip.setValue(dipStr)
                    this.writeBytes(16, IPv4ToBuffer(dipStr))
                }
            },
            options: {
                type: 'string',
                label: 'Options',
                minLength: 0,
                maxLength: 40 * 2,
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
