import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {BufferToUInt16, BufferToUInt32, BufferToUInt64, BufferToUInt8} from '../lib/BufferToNumber'
import {UInt16ToBuffer, UInt32ToBuffer, UInt64ToBuffer, UInt8ToBuffer} from '../lib/NumberToBuffer'
import {IPv6ToBuffer} from '../lib/IPToBuffer'
import {CodecModule} from '../types/CodecModule'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {UInt64ToHex} from '../lib/NumberToHex'
import {HexToUInt64} from '../lib/HexToNumber'

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

type OPTION_EOL = {
    option: TCPOption.End_of_Option_List
}

type OPTION_NOP = {
    option: TCPOption.No_Operation
}

type OPTION_MSS = {
    option: TCPOption.Maximum_Segment_Size
    mss: number
}

type OPTION_WINDOW_SCALE = {
    option: TCPOption.Window_Scale
    shift: number
}

type OPTION_SACK_PERMITTED = {
    option: TCPOption.Selective_Acknowledgment_Permitted
}

type OPTION_SACK = {
    option: TCPOption.Selective_Acknowledgment
    blocks: string[]
}

type OPTION_TS = {
    option: TCPOption.Timestamp
    tsval: number
    tsecr: number
}

type OPTION_UTO = {
    option: TCPOption.User_Timeout
    timeout: number
    granularity: number
}

type OPTION_TCP_AO = {
    option: TCPOption.TCP_Authentication_Option
    data: string
}

type OPTION_DEFAULT = {
    kind: number
    data: string
}

type OptionItem =
    OPTION_EOL
    | OPTION_NOP
    | OPTION_MSS
    | OPTION_WINDOW_SCALE
    | OPTION_SACK_PERMITTED
    | OPTION_SACK
    | OPTION_TS
    | OPTION_UTO
    | OPTION_TCP_AO
    | OPTION_DEFAULT

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
                            label: 'End of Option List',
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
                            label: 'No-Operation',
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
                            label: 'Maximum Segment Size',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.Maximum_Segment_Size]
                                },
                                mss: {
                                    type: 'integer',
                                    label: 'MSS',
                                    maximum: 65535,
                                    minimum: 0
                                }
                            }
                        },
                        //Kind = 3 (Window Scale)
                        {
                            type: 'object',
                            label: 'Window Scale',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.Window_Scale]
                                },
                                shift: {
                                    type: 'integer',
                                    label: 'Shift count',
                                    minimum: 0,
                                    maximum: 14
                                }
                            }
                        },
                        //Kind = 4 (Selective Acknowledgment Permitted, SACK-Permitted)
                        {
                            type: 'object',
                            label: 'Selective Acknowledgment Permitted',
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
                            label: 'Selective Acknowledgment',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.Selective_Acknowledgment]
                                },
                                blocks: {
                                    type: 'array',
                                    label: 'SACK Blocks',
                                    items: {
                                        type: 'string',
                                        maxLength: 16,
                                        minLength: 16,
                                        contentEncoding: StringContentEncodingEnum.HEX
                                    }
                                }
                            }
                        },
                        //Kind = 8 (Timestamp, TS)
                        {
                            type: 'object',
                            label: 'Timestamp',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.Timestamp]
                                },
                                tsval: {
                                    type: 'integer',
                                    label: 'TSval',
                                    minimum: 0,
                                    maximum: 4294967295
                                },
                                tsecr: {
                                    type: 'integer',
                                    label: 'TSecr',
                                    minimum: 0,
                                    maximum: 4294967295
                                }
                            }
                        },
                        //Kind = 28 (User Timeout, UTO)
                        {
                            type: 'object',
                            label: 'User Timeout',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.User_Timeout]
                                },
                                timeout: {
                                    type: 'integer',
                                    label: 'Timeout',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                granularity: {
                                    type: 'integer',
                                    label: 'Granularity',
                                    enum: [0, 1]
                                }
                            }
                        },
                        //Kind = 29 (TCP Authentication Option, TCP-AO)
                        {
                            type: 'object',
                            label: 'TCP Authentication Option',
                            properties: {
                                option: {
                                    type: 'string',
                                    label: 'Option',
                                    enum: [TCPOption.TCP_Authentication_Option]
                                },
                                data: {
                                    type: 'string',
                                    label: 'Data',
                                    contentEncoding: StringContentEncodingEnum.HEX
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
                },
                decode: (): void => {
                    const hdrLen: number = this.instance.hdrLen.getValue()
                    const optionsLength: number = hdrLen - this.length
                    if (!optionsLength) return
                    let optionOffset: number = this.length
                    const options: OptionItem[] = []
                    let index: number = 0
                    while (optionOffset < hdrLen) {
                        const kind: number = BufferToUInt8(this.readBytes(optionOffset, 1))
                        optionOffset += 1
                        switch (kind) {
                            //Kind = 0 (End of Option List, EOL)
                            case 0: {
                                options.push({
                                    option: TCPOption.End_of_Option_List
                                })
                            }
                                break
                            //Kind = 1 (No-Operation, NOP)
                            case 1: {
                                options.push({
                                    option: TCPOption.No_Operation
                                })
                            }
                                break
                            //Kind = 2 (Maximum Segment Size, MSS)
                            case 2: {
                                let length: number = BufferToUInt8(this.readBytes(optionOffset, 1))
                                if (length !== 4) this.recordError(this.instance.options.getPath(index), 'MSS option TLV length should be 4')
                                optionOffset += 1
                                let value: number = BufferToUInt16(this.readBytes(optionOffset, 2))
                                optionOffset += 2
                                options.push({
                                    option: TCPOption.Maximum_Segment_Size,
                                    mss: value
                                })
                            }
                                break
                            //Kind = 3 (Window Scale)
                            case 3: {
                                let length: number = BufferToUInt8(this.readBytes(optionOffset, 1))
                                if (length !== 3) this.recordError(this.instance.options.getPath(index), 'Window Scale option TLV length should be 3')
                                optionOffset += 1
                                let value: number = BufferToUInt8(this.readBytes(optionOffset, 1))
                                optionOffset += 1
                                if (value < 0 || value > 14) this.recordError(this.instance.options.getPath(index), 'Window Scale option TLV value should between 0 and 14')
                                options.push({
                                    option: TCPOption.Window_Scale,
                                    shift: value
                                })
                            }
                                break
                            //Kind = 4 (Selective Acknowledgment Permitted, SACK-Permitted)
                            case 4: {
                                let length: number = BufferToUInt8(this.readBytes(optionOffset, 1))
                                optionOffset += 1
                                if (length !== 2) this.recordError(this.instance.options.getPath(index), 'SACK-Permitted option TLV length should be 2')
                                options.push({
                                    option: TCPOption.Selective_Acknowledgment_Permitted
                                })
                            }
                                break
                            //Kind = 5 (Selective Acknowledgment, SACK)
                            case 5: {
                                let length: number = BufferToUInt8(this.readBytes(optionOffset, 1))
                                optionOffset += 1
                                let sackBlockTotalLength: number = length - 2
                                if (sackBlockTotalLength < 0) {
                                    this.recordError(this.instance.options.getPath(index), 'SACK option block count should not less than 0')
                                    sackBlockTotalLength = 0
                                }
                                let sackBlockCount: number = sackBlockTotalLength ? Math.floor(sackBlockTotalLength / 8) : 0
                                const sackBlocks: string[] = []
                                while (sackBlockCount > 0) {
                                    sackBlocks.push(UInt64ToHex(BigInt(`0x${BufferToUInt64(this.readBytes(optionOffset, 8)).toString(16)}`)))
                                    optionOffset += 8
                                    sackBlockCount -= 1
                                }
                                options.push({
                                    option: TCPOption.Selective_Acknowledgment,
                                    blocks: sackBlocks
                                })
                            }
                                break
                            //Kind = 8 (Timestamp, TS)
                            case 8: {
                                let length: number = BufferToUInt8(this.readBytes(optionOffset, 1))
                                optionOffset += 1
                                if (length !== 10) this.recordError(this.instance.options.getPath(index), 'Timestamp option TLV length should be 10')
                                let tsval: number = BufferToUInt32(this.readBytes(optionOffset, 4))
                                optionOffset += 4
                                let tsecr: number = BufferToUInt32(this.readBytes(optionOffset, 4))
                                optionOffset += 4
                                options.push({
                                    option: TCPOption.Timestamp,
                                    tsval: tsval,
                                    tsecr: tsecr
                                })
                            }
                                break
                            //Kind = 28 (User Timeout, UTO)
                            case 28: {
                                let length: number = BufferToUInt8(this.readBytes(optionOffset, 1))
                                optionOffset += 1
                                if (length !== 5) this.recordError(this.instance.options.getPath(index), 'UTO option TLV length should be 5')
                                let timeout: number = BufferToUInt16(this.readBytes(optionOffset, 2))
                                optionOffset += 2
                                let granularity: number = BufferToUInt8(this.readBytes(optionOffset, 1))
                                optionOffset += 1
                                options.push({
                                    option: TCPOption.User_Timeout,
                                    timeout: timeout,
                                    granularity: granularity
                                })
                            }
                                break
                            //Kind = 29 (TCP Authentication Option, TCP-AO)
                            case 29: {
                                let length: number = BufferToUInt8(this.readBytes(optionOffset, 1))
                                optionOffset += 1
                                let dataLength: number = length - 2
                                if (dataLength < 0) {
                                    this.recordError(this.instance.options.getPath(index), 'TCP Authentication Option TLV length should not less than 2')
                                    dataLength = 0
                                }
                                let data: Buffer
                                if (dataLength) {
                                    data = this.readBytes(optionOffset, dataLength)
                                    optionOffset += dataLength
                                } else {
                                    data = Buffer.from([])
                                }
                                options.push({
                                    option: TCPOption.TCP_Authentication_Option,
                                    data: data.toString('hex')
                                })
                            }
                                break
                            default: {
                                let length: number = BufferToUInt8(this.readBytes(optionOffset, 1))
                                let dataLength: number = length - 2
                                if (dataLength < 0) {
                                    this.recordError(this.instance.options.getPath(index), 'Option TLV length should not less than 2')
                                    dataLength = 0
                                }
                                let data: Buffer
                                if (dataLength) {
                                    data = this.readBytes(optionOffset, dataLength)
                                    optionOffset += dataLength
                                } else {
                                    data = Buffer.from([])
                                }
                                options.push({
                                    kind: kind,
                                    data: data.toString('hex')
                                })
                            }
                        }
                        index += 1
                    }
                    this.instance.options.setValue(options)
                },
                encode: (): void => {
                    const options: (OptionItem[]) | undefined = this.instance.options.getValue()
                    if (!options) return
                    let optionOffset: number = this.length
                    options.forEach((optionItem: OptionItem): void => {
                        const namedOptionItem: OPTION_EOL | OPTION_NOP | OPTION_MSS | OPTION_WINDOW_SCALE | OPTION_SACK_PERMITTED | OPTION_SACK | OPTION_TS | OPTION_UTO | OPTION_TCP_AO = optionItem as any
                        switch (namedOptionItem.option) {
                            case TCPOption.End_of_Option_List: {
                                const optionEOL: OPTION_EOL = optionItem as OPTION_EOL
                                this.writeBytes(optionOffset, UInt8ToBuffer(0))
                                optionOffset += 1
                                return
                            }
                            case TCPOption.No_Operation: {
                                const optionNOP: OPTION_NOP = optionItem as OPTION_NOP
                                this.writeBytes(optionOffset, UInt8ToBuffer(1))
                                optionOffset += 1
                                return
                            }
                            case TCPOption.Maximum_Segment_Size: {
                                const optionMSS: OPTION_MSS = optionItem as OPTION_MSS
                                const mssBuffer: Buffer = Buffer.concat([
                                    UInt8ToBuffer(2),
                                    UInt8ToBuffer(4),
                                    UInt16ToBuffer(optionMSS.mss)
                                ])
                                this.writeBytes(optionOffset, mssBuffer)
                                optionOffset += mssBuffer.length
                                return
                            }
                            case TCPOption.Window_Scale: {
                                const optionWS: OPTION_WINDOW_SCALE = optionItem as OPTION_WINDOW_SCALE
                                const wsBuffer: Buffer = Buffer.concat([
                                    UInt8ToBuffer(3),
                                    UInt8ToBuffer(3),
                                    UInt8ToBuffer(optionWS.shift)
                                ])
                                this.writeBytes(optionOffset, wsBuffer)
                                optionOffset += wsBuffer.length
                                return
                            }
                            case TCPOption.Selective_Acknowledgment_Permitted: {
                                const optionSackPermitted: OPTION_SACK_PERMITTED = optionItem as OPTION_SACK_PERMITTED
                                const sackPermittedBuffer: Buffer = Buffer.concat([
                                    UInt8ToBuffer(4),
                                    UInt8ToBuffer(2)
                                ])
                                this.writeBytes(optionOffset, sackPermittedBuffer)
                                optionOffset += sackPermittedBuffer.length
                                return
                            }
                            case TCPOption.Selective_Acknowledgment: {
                                const optionSack: OPTION_SACK = optionItem as OPTION_SACK
                                const kindBuffer: Buffer = UInt8ToBuffer(5)
                                let length: number = 2
                                let blocksBuffer: Buffer = Buffer.from([])
                                optionSack.blocks.forEach((block: string): void => {
                                    blocksBuffer = Buffer.concat([blocksBuffer, UInt64ToBuffer(HexToUInt64(block))])
                                })
                                const sackBuffer: Buffer = Buffer.concat([kindBuffer, UInt8ToBuffer(length + blocksBuffer.length), blocksBuffer])
                                this.writeBytes(optionOffset, sackBuffer)
                                optionOffset += sackBuffer.length
                                return
                            }
                            case TCPOption.Timestamp: {
                                const optionTS: OPTION_TS = optionItem as OPTION_TS
                                const tsBuffer: Buffer = Buffer.concat([
                                    UInt8ToBuffer(8),
                                    UInt8ToBuffer(10),
                                    UInt32ToBuffer(optionTS.tsval ? optionTS.tsval : 0),
                                    UInt32ToBuffer(optionTS.tsecr ? optionTS.tsecr : 0)
                                ])
                                this.writeBytes(optionOffset, tsBuffer)
                                optionOffset += tsBuffer.length
                                return
                            }
                            case TCPOption.User_Timeout: {
                                const optionUTO: OPTION_UTO = optionItem as OPTION_UTO
                                const utoBuffer: Buffer = Buffer.concat([
                                    UInt8ToBuffer(28),
                                    UInt8ToBuffer(5),
                                    UInt16ToBuffer(optionUTO.timeout ? optionUTO.timeout : 0),
                                    UInt8ToBuffer(optionUTO.granularity ? optionUTO.granularity : 0)
                                ])
                                this.writeBytes(optionOffset, utoBuffer)
                                optionOffset += utoBuffer.length
                                return
                            }
                            case TCPOption.TCP_Authentication_Option: {
                                const optionTcpAo: OPTION_TCP_AO = optionItem as OPTION_TCP_AO
                                const kindBuffer: Buffer = UInt8ToBuffer(29)
                                const dataBuffer: Buffer = Buffer.from(optionTcpAo.data, 'hex')
                                const lengthBuffer: Buffer = UInt8ToBuffer(dataBuffer.length + 2)
                                const tcpAoBuffer: Buffer = Buffer.concat([kindBuffer, lengthBuffer, dataBuffer])
                                this.writeBytes(optionOffset, tcpAoBuffer)
                                optionOffset += tcpAoBuffer.length
                                return
                            }
                            default: {
                                const defaultOptionItem: OPTION_DEFAULT = optionItem as OPTION_DEFAULT
                                const kind: number = defaultOptionItem.kind
                                const hexBuffer: Buffer = Buffer.from(defaultOptionItem.data.toString(), 'hex')
                                const length: number = hexBuffer.length + 2
                                const defaultOptionBuffer: Buffer = Buffer.concat([UInt8ToBuffer(kind), UInt8ToBuffer(length), hexBuffer])
                                this.writeBytes(optionOffset, defaultOptionBuffer)
                                optionOffset += defaultOptionBuffer.length
                            }
                        }
                    })
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
