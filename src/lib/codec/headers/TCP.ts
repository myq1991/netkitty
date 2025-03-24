import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {BufferToUInt16, BufferToUInt32} from '../lib/BufferToNumber'
import {UInt16ToBuffer, UInt32ToBuffer} from '../lib/NumberToBuffer'
import {IPv6ToBuffer} from '../lib/IPToBuffer'
import {CodecModule} from '../types/CodecModule'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

enum TCPOption {
    End_of_Option_List = 'EOL',
    No_Operation = 'NOP',
    Maximum_Segment_Size = 'MSS',
    Window_Scale = 'Window-Scale',
    Selective_Acknowledgment_Permitted = 'SACK-Permitted',
    Selective_Acknowledgment = 'SACK',
    Timestamp = 'TS',
    User_Timeout = 'UTO',
    TCP_Authentication_Option = 'TCP-AO'
}

export default class TCP extends BaseHeader {

    /**
     * Calculate TCP Checksum
     * @param tcpHeaderBuffer
     * @protected
     */
    protected calculateTCPChecksum(tcpHeaderBuffer: Buffer): number {
        const ipVersion: number = this.prevCodecModule.instance.version.getValue()
        let pseudoHeaderBuffer: Buffer = Buffer.from([])
        const sourceIp: string = this.prevCodecModule.instance.sip.getValue()
        const destinationIp: string = this.prevCodecModule.instance.dip.getValue()
        if (ipVersion === 4) {
            //4 Bytes
            const sourceIPv4Buffer: Buffer = Buffer.from(sourceIp.split('.').map((value: string): number => parseInt(value)))
            const destinationIPv4Buffer: Buffer = Buffer.from(destinationIp.split('.').map((value: string): number => parseInt(value)))
            //IPv4 Pseudo header
            pseudoHeaderBuffer = Buffer.concat([
                sourceIPv4Buffer,
                destinationIPv4Buffer,
                Buffer.from('00', 'hex'), //Reserved field
                Buffer.from('06', 'hex'), //Protocol type (TCP = 6)
                Buffer.from([(this.length >> 8) & 0xFF]),
                Buffer.from([this.length & 0xFF])
            ])
        } else if (ipVersion === 6) {
            //16 Bytes
            const sourceIPv6Buffer: Buffer = IPv6ToBuffer(sourceIp)
            const destinationIPv6Buffer: Buffer = IPv6ToBuffer(destinationIp)
            //IPv6 Pseudo header
            pseudoHeaderBuffer = Buffer.concat([
                sourceIPv6Buffer,
                destinationIPv6Buffer,
                Buffer.from('00', 'hex'), //Reserved field
                Buffer.from('00', 'hex'), //Reserved field
                Buffer.from('00', 'hex'), //Reserved field
                Buffer.from('06', 'hex'), //Protocol type (TCP = 6)
                Buffer.from([(this.length >> 8) & 0xFF]),
                Buffer.from([this.length & 0xFF])
            ])
        } else {
            return 0
        }
        const dataBuffer: Buffer = Buffer.concat([pseudoHeaderBuffer, tcpHeaderBuffer])
        const data: Uint8Array = Uint8Array.from(dataBuffer)
        let sum: number = 0
        for (let i: number = 0; i < data.length; i += 2) sum += (data[i] << 8) + (data[i + 1] || 0)
        while (sum >>> 16) sum = (sum & 0xFFFF) + (sum >>> 16)
        return (~sum) & 0xFFFF
    }

    public SCHEMA: ProtocolJSONSchema = {
        properties: {
            srcport: {
                type: 'integer',
                label: 'Source Port',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.srcport.setValue(BufferToUInt16(this.readBytes(0, 2)))
                },
                encode: (): void => {
                    let srcport: number = this.instance.srcport.getValue()
                    srcport = srcport ? srcport : 0
                    if (srcport > 65535) {
                        this.recordError(this.instance.srcport.getPath(), 'Maximum value is 65535')
                        srcport = 65535
                    }
                    if (srcport < 0) {
                        this.recordError(this.instance.srcport.getPath(), 'Minimum value is 0')
                        srcport = 0
                    }
                    this.writeBytes(0, UInt16ToBuffer(srcport))
                }
            },
            dstport: {
                type: 'integer',
                label: 'Destination Port',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.dstport.setValue(BufferToUInt16(this.readBytes(2, 2)))
                },
                encode: (): void => {
                    let dstport: number = this.instance.dstport.getValue()
                    dstport = dstport ? dstport : 0
                    if (dstport > 65535) {
                        this.recordError(this.instance.dstport.getPath(), 'Maximum value is 65535')
                        dstport = 65535
                    }
                    if (dstport < 0) {
                        this.recordError(this.instance.dstport.getPath(), 'Minimum value is 0')
                        dstport = 0
                    }
                    this.writeBytes(2, UInt16ToBuffer(dstport))
                }
            },
            seq: {
                type: 'integer',
                label: 'Sequence Number',
                minimum: 0,
                maximum: 4294967295,
                decode: (): void => {
                    this.instance.seq.setValue(BufferToUInt32(this.readBytes(4, 4)))
                },
                encode: (): void => {
                    let seqNum: number = this.instance.seq.getValue()
                    seqNum = seqNum ? seqNum : 0
                    if (seqNum > 4294967295) {
                        this.recordError(this.instance.seq.getPath(), 'Maximum value is 4294967295')
                        seqNum = 4294967295
                    }
                    if (seqNum < 0) {
                        this.recordError(this.instance.seq.getPath(), 'Minimum value is 0')
                        seqNum = 0
                    }
                    this.writeBytes(4, UInt32ToBuffer(seqNum))
                }
            },
            ack: {
                type: 'integer',
                label: 'Acknowledgment Number',
                minimum: 0,
                maximum: 4294967295,
                decode: (): void => {
                    this.instance.ack.setValue(BufferToUInt32(this.readBytes(8, 4)))
                },
                encode: (): void => {
                    let ackNum: number = this.instance.ack.getValue()
                    ackNum = ackNum ? ackNum : 0
                    if (ackNum > 4294967295) {
                        this.recordError(this.instance.ack.getPath(), 'Maximum value is 4294967295')
                        ackNum = 4294967295
                    }
                    if (ackNum < 0) {
                        this.recordError(this.instance.ack.getPath(), 'Minimum value is 0')
                        ackNum = 0
                    }
                    this.writeBytes(8, UInt32ToBuffer(ackNum))
                }
            },
            hdrLen: {
                type: 'integer',
                label: 'Header Length',
                minimum: 0,
                maximum: 60,
                decode: (): void => {
                    this.instance.hdrLen.setValue(this.readBits(12, 1, 0, 4) * 4)
                },
                encode: (): void => {
                    let hdrLen: number = this.instance.hdrLen.getValue()
                    hdrLen = hdrLen ? hdrLen : 0
                    hdrLen = 0//TODO 调试用
                    if (hdrLen) {
                        this.writeBits(12, 1, 0, 4, Math.floor(hdrLen / 4))
                    } else {
                        this.addPostSelfEncodeHandler((): void => {
                            this.writeBits(12, 1, 0, 4, Math.floor(this.length / 4))
                        }, 1)
                    }
                }
            },
            flags: {
                type: 'object',
                label: 'Flags',
                properties: {
                    res: {
                        type: 'integer',
                        label: 'Reserved',
                        minimum: 0,
                        maximum: 7,
                        decode: (): void => {
                            this.instance.flags.res.setValue(this.readBits(12, 1, 4, 3))
                        },
                        encode: (): void => {
                            let reserved: number = this.instance.flags.res.getValue()
                            reserved = reserved ? reserved : 0
                            if (reserved > 7) {
                                this.recordError(this.instance.flags.res.getPath(), 'Maximum value is 7')
                                reserved = 7
                            }
                            if (reserved < 0) {
                                this.recordError(this.instance.flags.res.getPath(), 'Minimum value is 0')
                                reserved = 0
                            }
                            this.writeBits(12, 1, 4, 3, reserved)
                        }
                    },
                    ae: {
                        type: 'boolean',
                        label: 'Accurate ECN',
                        decode: (): void => {
                            this.instance.flags.ae.setValue(!!this.readBits(12, 1, 7, 1))
                        },
                        encode: (): void => {
                            let accurateECN: boolean = !!this.instance.flags.ae.getValue()
                            this.writeBits(12, 1, 7, 1, accurateECN ? 1 : 0)
                        }
                    },
                    cwr: {
                        type: 'boolean',
                        label: 'Congestion Window Reduced',
                        decode: (): void => {
                            this.instance.flags.cwr.setValue(!!this.readBits(13, 1, 0, 1))
                        },
                        encode: (): void => {
                            let congestionWindowReduced: boolean = !!this.instance.flags.cwr.getValue()
                            this.writeBits(13, 1, 0, 1, congestionWindowReduced ? 1 : 0)
                        }
                    },
                    ece: {
                        type: 'boolean',
                        label: 'ECN-Echo',
                        decode: (): void => {
                            this.instance.flags.ece.setValue(!!this.readBits(13, 1, 1, 1))
                        },
                        encode: (): void => {
                            let ECNEcho: boolean = !!this.instance.flags.ece.getValue()
                            this.writeBits(13, 1, 1, 1, ECNEcho ? 1 : 0)
                        }
                    },
                    urg: {
                        type: 'boolean',
                        label: 'Urgent',
                        decode: (): void => {
                            this.instance.flags.urg.setValue(!!this.readBits(13, 1, 2, 1))
                        },
                        encode: (): void => {
                            let urgent: boolean = !!this.instance.flags.urg.getValue()
                            this.writeBits(13, 1, 2, 1, urgent ? 1 : 0)
                        }
                    },
                    ack: {
                        type: 'boolean',
                        label: 'Acknowledgment',
                        decode: (): void => {
                            this.instance.flags.ack.setValue(!!this.readBits(13, 1, 3, 1))
                        },
                        encode: (): void => {
                            let acknowledgment: boolean = !!this.instance.flags.ack.getValue()
                            this.writeBits(13, 1, 3, 1, acknowledgment ? 1 : 0)
                        }
                    },
                    push: {
                        type: 'boolean',
                        label: 'Push',
                        decode: (): void => {
                            this.instance.flags.push.setValue(!!this.readBits(13, 1, 4, 1))
                        },
                        encode: (): void => {
                            let push: boolean = !!this.instance.flags.push.getValue()
                            this.writeBits(13, 1, 4, 1, push ? 1 : 0)
                        }
                    },
                    rst: {
                        type: 'boolean',
                        label: 'Reset',
                        decode: (): void => {
                            this.instance.flags.rst.setValue(!!this.readBits(13, 1, 5, 1))
                        },
                        encode: (): void => {
                            let reset: boolean = !!this.instance.flags.rst.getValue()
                            this.writeBits(13, 1, 5, 1, reset ? 1 : 0)
                        }
                    },
                    syn: {
                        type: 'boolean',
                        label: 'Syn',
                        decode: (): void => {
                            this.instance.flags.syn.setValue(!!this.readBits(13, 1, 6, 1))
                        },
                        encode: (): void => {
                            let syn: boolean = !!this.instance.flags.syn.getValue()
                            this.writeBits(13, 1, 6, 1, syn ? 1 : 0)
                        }
                    },
                    fin: {
                        type: 'boolean',
                        label: 'Fin',
                        decode: (): void => {
                            this.instance.flags.fin.setValue(!!this.readBits(13, 1, 7, 1))
                        },
                        encode: (): void => {
                            let fin: boolean = !!this.instance.flags.fin.getValue()
                            this.writeBits(13, 1, 7, 1, fin ? 1 : 0)
                        }
                    }
                }
            },
            window: {
                type: 'integer',
                label: 'Window Size',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.window.setValue(BufferToUInt16(this.readBytes(14, 2)))
                },
                encode: (): void => {
                    let windowSize: number = this.instance.window.getValue()
                    windowSize = windowSize ? windowSize : 0
                    if (windowSize > 65535) {
                        this.recordError(this.instance.window.getPath(), 'Maximum value is 65535')
                        windowSize = 65535
                    }
                    if (windowSize < 0) {
                        this.recordError(this.instance.window.getPath(), 'Minimum value is 0')
                        windowSize = 0
                    }
                    this.writeBytes(14, UInt16ToBuffer(windowSize))
                }
            },
            checksum: {
                type: 'integer',
                label: 'Checksum',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.checksum.setValue(BufferToUInt16(this.readBytes(16, 2)))
                },
                encode: (): void => {
                    let checksum: number = this.instance.checksum.getValue()
                    checksum = checksum ? checksum : 0
                    checksum = 0//TODO 调试用
                    if (checksum) {
                        this.writeBytes(16, UInt16ToBuffer(checksum))
                    } else {
                        this.addPostPacketEncodeHandler((): void => {
                            //Calculate checksum after packet encoded
                            let startPos: number = 0
                            let endPos: number = 0
                            this.codecModules.forEach((codecModule: CodecModule): void => {
                                if (codecModule === this) startPos = codecModule.startPos
                                endPos = codecModule.endPos > endPos ? codecModule.endPos : endPos
                            })
                            const t1 = this.packet.subarray(startPos, endPos)
                            console.log(startPos, endPos)
                            console.log(t1, t1.length)
                            this.writeBytes(16, UInt16ToBuffer(this.calculateTCPChecksum(this.packet.subarray(startPos, endPos))))
                        }, 100)
                    }
                }
            },
            urgPtr: {
                type: 'integer',
                label: 'Urgent Pointer',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.urgPtr.setValue(BufferToUInt16(this.readBytes(18, 2)))
                },
                encode: (): void => {
                    let urgPtr: number = this.instance.urgPtr.getValue()
                    urgPtr = urgPtr ? urgPtr : 0
                    if (urgPtr > 65535) {
                        this.recordError(this.instance.urgPtr.getPath(), 'Maximum value is 65535')
                        urgPtr = 65535
                    }
                    if (urgPtr < 0) {
                        this.recordError(this.instance.urgPtr.getPath(), 'Minimum value is 0')
                        urgPtr = 0
                    }
                    this.writeBytes(18, UInt16ToBuffer(urgPtr))
                }
            },
            options: {
                type: 'array',
                label: 'Options',
                items: {
                    allOf: [
                        //Kind = 0 (End of Option List, EOL)
                        {
                            type: 'object',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.End_of_Option_List]
                                }
                            }
                        },
                        //Kind = 1 (No-Operation, NOP)
                        {
                            type: 'object',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.No_Operation]
                                }
                            }
                        },
                        //Kind = 2 (Maximum Segment Size, MSS)
                        {
                            type: 'object',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.Maximum_Segment_Size]
                                }
                            }
                        },
                        //Kind = 3 (Window Scale)
                        {
                            type: 'object',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.Window_Scale]
                                }
                            }
                        },
                        //Kind = 4 (Selective Acknowledgment Permitted, SACK-Permitted)
                        {
                            type: 'object',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.Selective_Acknowledgment_Permitted]
                                }
                            }
                        },
                        //Kind = 5 (Selective Acknowledgment, SACK)
                        {
                            type: 'object',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.Selective_Acknowledgment]
                                }
                            }
                        },
                        //Kind = 8 (Timestamp, TS)
                        {
                            type: 'object',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.Timestamp]
                                }
                            }
                        },
                        //Kind = 28 (User Timeout, UTO)
                        {
                            type: 'object',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.User_Timeout]
                                }
                            }
                        },
                        //Kind = 29 (TCP Authentication Option, TCP-AO)
                        {
                            type: 'object',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.TCP_Authentication_Option]
                                }
                            }
                        },
                        //Default
                        {
                            type: 'object',
                            properties: {
                                kind: {
                                    type: 'integer',
                                    label: 'Kind'
                                },
                                data: {
                                    type: 'string',
                                    contentEncoding: StringContentEncodingEnum.HEX,
                                    label: 'Data'
                                }
                            }
                        }
                    ]
                }
            }
        }
    }

    public id: string = 'tcp'

    public name: string = 'Transmission Control Protocol'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.instance.protocol.getValue() === 0x06) return true
        return false
    }

}
