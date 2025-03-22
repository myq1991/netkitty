import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {UInt16ToHex, UInt32ToHex, UInt8ToHex} from '../lib/NumberToHex'
import {CodecModule} from '../types/CodecModule'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

export default class IPv4 extends BaseHeader {

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
                    this.instance.version = this.readBits(0, 1, 0, 4)
                    if (this.instance.version !== 4) this.recordError('version', 'IPv4 version should be 4')
                },
                encode: (): void => {
                    let version: number = this.instance.version as number
                    version = parseInt((version ? version : 4).toString())
                    version = version > 15 ? 15 : version
                    version = version < 0 ? 0 : version
                    if (version !== 4) this.recordError('version', 'IPv4 version should be 4')
                    this.writeBits(0, 1, 0, 4, version)
                }
            },
            hdrLen: {
                type: 'integer',
                label: 'Header Length',
                minimum: 20,
                maximum: 60,
                decode: (): void => {
                    this.instance.hdrLen = this.readBits(0, 1, 4, 4) * 4
                },
                encode: (): void => {
                    let headerLength: number = this.instance.hdrLen as number
                    if (!headerLength) headerLength = headerLength ? headerLength : 0
                    if (headerLength) headerLength = Math.floor(headerLength / 4)
                    this.writeBits(0, 1, 4, 4, headerLength)
                    if (!headerLength) this.addPostSelfEncodeHandler((): void => {
                        this.instance.hdrLen = this.length
                        this.writeBits(0, 1, 4, 4, Math.floor(this.length / 4))
                    }, 10)
                }
            },
            dsfield: {
                type: 'object',
                label: 'Differentiated Services Field',
                decode: (): void => {
                    this.instance.dsfield = {}
                },
                properties: {
                    dscp: {
                        type: 'integer',
                        minimum: 0,
                        maximum: 63,
                        label: 'Differentiated Services Codepoint',
                        decode: (): void => {
                            this.instance.dsfield['dscp'] = this.readBits(1, 1, 0, 6)
                        },
                        encode: (): void => {
                            let dscp: number = this.instance.dsfield['dscp'] as number
                            dscp = dscp ? dscp : 0
                            this.writeBits(1, 1, 0, 6, dscp)
                        }
                    },
                    ecn: {
                        type: 'integer',
                        label: 'Explicit Congestion Notification',
                        decode: (): void => {
                            this.instance.dsfield['ecn'] = this.readBits(1, 1, 6, 2)
                        },
                        encode: (): void => {
                            let ecn: number = this.instance.dsfield['ecn'] as number
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
                    this.instance.length = parseInt(this.readBytes(2, 2).toString('hex'), 16)
                },
                encode: (): void => {
                    //This field's real value needs down stream codec invoke recode to fill
                    let length: number = this.instance.length as number
                    length = length ? length : 0
                    if (length) {
                        this.writeBytes(2, Buffer.from(UInt16ToHex(length), 'hex'))
                    } else {
                        this.addPostPacketEncodeHandler((): void => {
                            let startCount: boolean = false
                            let totalLength: number = 0
                            this.codecModules.forEach((codecModule: CodecModule): void => {
                                if (codecModule === this) startCount = true
                                if (startCount) totalLength += codecModule.length
                            })
                            this.writeBytes(2, Buffer.from(UInt16ToHex(totalLength), 'hex'))
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
                    this.instance.id = parseInt(this.readBytes(4, 2).toString('hex'), 16)
                },
                encode: (): void => {
                    if (!this.instance.id) this.recordError('id', 'Not Found')
                    let id: number = this.instance.id as number
                    id = id ? id : 0
                    this.writeBytes(4, Buffer.from(UInt16ToHex(id), 'hex'))
                }
            },
            flags: {
                type: 'object',
                label: 'Flags',
                decode: (): void => {
                    this.instance.flags = {}
                },
                properties: {
                    rb: {
                        type: 'integer',
                        enum: [0, 1],
                        label: 'Reserved bit',
                        decode: (): void => {
                            this.instance.flags['rb'] = this.readBits(6, 1, 0, 1)
                        },
                        encode: (): void => {
                            let rb: number
                            if (this.instance.flags === undefined || this.instance.flags['rb'] === undefined) {
                                this.recordError('flags.rb', 'Not Found')
                                rb = 0
                            } else {
                                rb = this.instance.flags['rb'] as number
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
                            this.instance.flags['df'] = this.readBits(6, 1, 1, 1)
                        },
                        encode: (): void => {
                            let df: number
                            if (this.instance.flags === undefined || this.instance.flags['df'] === undefined) {
                                this.recordError('flags.df', 'Not Found')
                                df = 1
                            } else {
                                df = this.instance.flags['df'] as number
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
                            this.instance.flags['mf'] = this.readBits(6, 1, 2, 1)
                        },
                        encode: (): void => {
                            let mf: number
                            if (this.instance.flags === undefined || this.instance.flags['mf'] === undefined) {
                                this.recordError('flags.mf', 'Not Found')
                                mf = 0
                            } else {
                                mf = this.instance.flags['mf'] as number
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
                    this.instance.fragOffset = this.readBits(6, 2, 3, 13)
                },
                encode: (): void => {
                    if (this.instance.fragOffset === undefined) this.recordError('fragOffset', 'Not Found')
                    let fragOffset: number = this.instance.fragOffset as number
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
                    this.instance.ttl = parseInt(this.readBytes(8, 1).toString('hex'), 16)
                },
                encode: (): void => {
                    if (this.instance.ttl === undefined) this.recordError('ttl', 'Not Found')
                    let ttl: number = this.instance.ttl as number
                    ttl = ttl ? ttl : 0
                    this.writeBytes(8, Buffer.from(UInt8ToHex(ttl), 'hex'))
                }
            },
            protocol: {
                type: 'integer',
                label: 'Protocol',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.protocol = parseInt(this.readBytes(9, 1).toString('hex'), 16)
                },
                encode: (): void => {
                    if (this.instance.protocol === undefined) this.recordError('protocol', 'Not Found')
                    let protocol: number = this.instance.protocol as number
                    protocol = protocol ? protocol : 0
                    this.writeBytes(9, Buffer.from(UInt8ToHex(protocol), 'hex'))
                }
            },
            checksum: {
                type: 'integer',
                label: 'Header Checksum',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.checksum = parseInt(this.readBytes(10, 2).toString('hex'), 16)
                },
                encode: (): void => {
                    let checksum: number = this.instance.checksum ? this.instance.checksum as number : 0
                    checksum = parseInt(checksum.toString())
                    checksum = checksum ? checksum : 0
                    checksum = checksum > 65535 ? 65535 : checksum
                    checksum = checksum < 0 ? 0 : checksum
                    if (checksum) {
                        this.writeBytes(10, Buffer.from(UInt16ToHex(checksum), 'hex'))
                    } else {
                        this.writeBytes(10, Buffer.alloc(2, 0))
                        this.addPostPacketEncodeHandler((): void => {
                            this.writeBytes(10, Buffer.from(UInt16ToHex(this.calculateIPv4Checksum(this.packet.subarray(this.startPos, this.endPos))), 'hex'))
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
                    this.instance.sip = Array.from(sipBuffer).join('.')
                },
                encode: (): void => {
                    if (this.instance.sip === undefined) {
                        this.recordError('sip', 'Not Found')
                        this.instance.sip = '0.0.0.0'
                    }
                    const sipStr: string = this.instance.sip.toString()
                    const numArr: number[] = sipStr.split('.').map(value => parseInt(value)).map(value => value ? value : 0)
                    this.writeBytes(12, Buffer.from(UInt32ToHex(parseInt(Buffer.from(numArr).toString('hex'), 16)), 'hex'))
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
                    this.instance.dip = Array.from(dipBuffer).join('.')
                },
                encode: (): void => {
                    if (this.instance.dip === undefined) {
                        this.recordError('dip', 'Not Found')
                        this.instance.dip = '0.0.0.0'
                    }
                    const dipStr: string = this.instance.dip.toString()
                    const numArr: number[] = dipStr.split('.').map(value => parseInt(value)).map(value => value ? value : 0)
                    this.writeBytes(16, Buffer.from(UInt32ToHex(parseInt(Buffer.from(numArr).toString('hex'), 16)), 'hex'))
                }
            },
            options: {
                type: 'string',
                label: 'Options',
                contentEncoding: StringContentEncodingEnum.HEX,
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            padding: {
                type: 'string',
                label: 'Padding',
                contentEncoding: StringContentEncodingEnum.BINARY,
                //the IPv4 Header should have a length that a multiple of 32 bits
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            }
        }
    }

    public id: string = 'ipv4'

    public name: string = 'IPv4'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.etherType === 0x0800
    }
}
