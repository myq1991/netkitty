import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {DemuxProducer} from '../types/DemuxProducer'
import {UInt16ToHex} from '../../helper/NumberToHex'
import {CodecModule} from '../types/CodecModule'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {BufferToUInt16, BufferToUInt8} from '../../helper/BufferToNumber'
import {UInt16ToBuffer, UInt8ToBuffer} from '../../helper/NumberToBuffer'
import {BufferToHex} from '../../helper/BufferToHex'
import {IPv4ToBuffer} from '../../helper/IPToBuffer'
import {BufferToIPv4} from '../../helper/BufferToIP'
import {HexToBuffer} from '../../helper/HexToBuffer'

export class IPv4 extends BaseHeader {

    /**
     * Calculate IPv4 header checksum
     * @param headerBuffer
     * @protected
     */
    protected calculateIPv4Checksum(headerBuffer: Buffer): number {
        const header: Uint8Array = Uint8Array.from(headerBuffer)
        let sum: number = 0
        for (let i: number = 0; i < header.length; i += 2) {
            const word: number = (header[i] << 8) + (header[i + 1] || 0)
            sum += word
        }
        while (sum >>> 16) {
            sum = (sum & 0xFFFF) + (sum >>> 16)
        }
        return (~sum) & 0xFFFF
    }

    static #schemaCache: ProtocolJSONSchema | undefined

    //SCHEMA is built once per class and cached (④ prototype). Its field closures are plain functions
    //that take `this` dynamically — BaseHeader invokes each via .call(this) — so they capture no
    //instance and the whole structure is shareable, avoiding a full per-packet rebuild. Inner callbacks
    //(post-handlers, getValue callbacks) are arrows created when the function runs, capturing that
    //call's `this`, so caching does not cross-wire instances. Unmigrated headers still initialise
    //SCHEMA as an instance field.
    public get SCHEMA(): ProtocolJSONSchema {
        return (IPv4.#schemaCache ??= IPv4.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
        type: 'object',
        summary: '${sip} → ${dip}',
        properties: {
            version: {
                type: 'integer',
                label: 'Version',
                minimum: 0,
                maximum: 15,
                decode: function (this: IPv4): void {
                    this.instance.version.setValue(this.readBits(0, 1, 0, 4))
                    if (this.instance.version.getValue() !== 4) this.recordError(this.instance.version.getPath(), 'IPv4 version should be 4')
                },
                encode: function (this: IPv4): void {
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
                decode: function (this: IPv4): void {
                    this.instance.hdrLen.setValue(this.readBits(0, 1, 4, 4) * 4)
                },
                encode: function (this: IPv4): void {
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
                        decode: function (this: IPv4): void {
                            this.instance.dsfield.dscp.setValue(this.readBits(1, 1, 0, 6))
                        },
                        encode: function (this: IPv4): void {
                            const dscp: number = this.instance.dsfield.dscp.getValue(0)
                            this.instance.dsfield.dscp.setValue(dscp)
                            this.writeBits(1, 1, 0, 6, dscp)
                        }
                    },
                    ecn: {
                        type: 'integer',
                        label: 'Explicit Congestion Notification',
                        decode: function (this: IPv4): void {
                            this.instance.dsfield.ecn.setValue(this.readBits(1, 1, 6, 2))
                        },
                        encode: function (this: IPv4): void {
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
                decode: function (this: IPv4): void {
                    this.instance.length.setValue(BufferToUInt16(this.readBytes(2, 2)))
                },
                encode: function (this: IPv4): void {
                    //This field's real value needs down stream codec invoke recode to fill
                    const length: number = this.instance.length.getValue(0)
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
                decode: function (this: IPv4): void {
                    this.instance.id.setValue(BufferToUInt16(this.readBytes(4, 2)))
                },
                encode: function (this: IPv4): void {
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
                        decode: function (this: IPv4): void {
                            this.instance.flags.rb.setValue(this.readBits(6, 1, 0, 1))
                        },
                        encode: function (this: IPv4): void {
                            const rb: number = this.instance.flags.rb.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            this.instance.flags.rb.setValue(rb)
                            this.writeBits(6, 1, 0, 1, rb)
                        }
                    },
                    df: {
                        type: 'integer',
                        enum: [0, 1],
                        label: 'Don\'t fragment',
                        decode: function (this: IPv4): void {
                            this.instance.flags.df.setValue(this.readBits(6, 1, 1, 1))
                        },
                        encode: function (this: IPv4): void {
                            const df: number = this.instance.flags.df.getValue(1, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            this.instance.flags.df.setValue(df)
                            this.writeBits(6, 1, 1, 1, df)
                        }
                    },
                    mf: {
                        type: 'integer',
                        enum: [0, 1],
                        label: 'More fragments',
                        decode: function (this: IPv4): void {
                            this.instance.flags.mf.setValue(this.readBits(6, 1, 2, 1))
                        },
                        encode: function (this: IPv4): void {
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
                decode: function (this: IPv4): void {
                    this.instance.fragOffset.setValue(this.readBits(6, 2, 3, 13))
                },
                encode: function (this: IPv4): void {
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
                decode: function (this: IPv4): void {
                    this.instance.ttl.setValue(BufferToUInt8(this.readBytes(8, 1)))
                },
                encode: function (this: IPv4): void {
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
                decode: function (this: IPv4): void {
                    this.instance.protocol.setValue(BufferToUInt8(this.readBytes(9, 1)))
                },
                encode: function (this: IPv4): void {
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
                decode: function (this: IPv4): void {
                    this.instance.checksum.setValue(BufferToUInt16(this.readBytes(10, 2)))
                },
                encode: function (this: IPv4): void {
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
                contentEncoding: StringContentEncodingEnum.IPv4,
                decode: function (this: IPv4): void {
                    const sipBuffer: Buffer = this.readBytes(12, 4)
                    this.instance.sip.setValue(BufferToIPv4(sipBuffer))
                },
                encode: function (this: IPv4): void {
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
                contentEncoding: StringContentEncodingEnum.IPv4,
                decode: function (this: IPv4): void {
                    const dipBuffer: Buffer = this.readBytes(16, 4)
                    this.instance.dip.setValue(BufferToIPv4(dipBuffer))
                },
                encode: function (this: IPv4): void {
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
                decode: function (this: IPv4): void {
                    if (this.length < (this.instance.hdrLen.getValue())) {
                        this.instance.options.setValue(BufferToHex(this.readBytes(this.length, (this.instance.hdrLen.getValue()) - this.length)))
                    }
                },
                encode: function (this: IPv4): void {
                    if (!this.instance.options.isUndefined()) {
                        let optionsBuffer: Buffer = HexToBuffer(this.instance.options.getValue(''))
                        if (optionsBuffer.length > 40) optionsBuffer = optionsBuffer.subarray(0, 40)
                        const estimateHdrLen: number = this.length + optionsBuffer.length
                        if (estimateHdrLen % 4) {
                            /**
                             * IPv4 Header should have a length that a multiple of 32 bits
                             * @see https://learningnetwork.cisco.com/s/question/0D53i00000Kt6hHCAR/padding-field-on-ipv4-header
                             */
                            optionsBuffer = Buffer.concat([optionsBuffer, Buffer.alloc((4 - estimateHdrLen % 4) % 4, 0)])
                        }
                        this.writeBytes(this.length, optionsBuffer)
                    }
                }
            }
        }
    }
    }

    public readonly id: string = 'ipv4'

    public readonly matchKeys: string[] = ['ethertype:0800']

    //Also in the heuristic chain so IPv4 can be recognized as the inner payload of a bare-IP tunnel
    //(GTP-U G-PDU), which carries no inner-protocol field. The etherType path below still handles the
    //normal ethertype:0800 bucket, so ethernet-parented IPv4 is byte-identical to before.
    public readonly heuristicFallback: boolean = true

    public readonly demuxProducers: DemuxProducer[] = [{field: 'protocol', namespace: 'ipproto', kind: 'uint'}]

    public readonly name: string = 'Internet Protocol Version 4'

    public readonly nickname: string = 'IPv4'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        //Normal path (unchanged): a parent that demuxed to IPv4 via its etherType field.
        if (this.prevCodecModule.instance.etherType.getValue() === UInt16ToHex(0x0800)) return true
        //Bare-IP tunnel path: GTP-U (and future discriminator-less IP tunnels) carry no inner-protocol
        //field, so match by the IPv4 version nibble. The tunnel-parent id gate MUST come first — a 4-bit
        //nibble alone is too weak a signature (many TCP/TLS payloads begin 0x4x).
        if (['gtp'].includes(this.prevCodecModule.id) && (this.readBytes(0, 1, true)[0] >> 4) === 4) return true
        //Typed-tunnel path: GENEVE carries a Protocol Type (an EtherType), so trust that self-describing
        //field rather than the weak version nibble — the ethertype demux already routed us here.
        if (this.prevCodecModule.id === 'geneve' && this.prevCodecModule.instance.protocolType.getValue() === UInt16ToHex(0x0800)) return true
        return false
    }
}
