import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import TLV from 'node-tlv'
import {
    HexToFloat32,
    HexToInt16,
    HexToInt32,
    HexToInt64,
    HexToInt8,
    HexToUInt16,
    HexToUInt32,
    HexToUInt8
} from '../../helper/HexToNumber'
import {
    Float32ToBERHex,
    Int16ToBERHex,
    Int32ToBERHex,
    Int64ToBERHex,
    Int8ToBERHex,
    UInt16ToBERHex,
    UInt32ToBERHex,
    UInt8ToBERHex
} from '../../helper/NumberToBERHex'
import {UInt16ToHex} from '../../helper/NumberToHex'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {UInt32ToBERBuffer} from '../../helper/NumberToBERBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {GetBERIntegerLengthFromBuffer} from '../lib/GetBERIntegerLengthFromBuffer'

enum ItemDataType {
    Boolean = 'Boolean',
    INT8 = 'INT8',
    INT16 = 'INT16',
    INT32 = 'INT32',
    INT64 = 'INT64',
    INT8U = 'INT8U',
    INT16U = 'INT16U',
    INT32U = 'INT32U',
    FLOAT32 = 'FLOAT32',
    CODEDENUM = 'CODED-ENUM',
    OCTETSTRING = 'OCTET-STRING',
    VISIBLESTRING = 'VISIBLE-STRING',
    TimeStamp = 'TimeStamp',
    Quality = 'Quality',
    Structure = 'Structure'
}

type BooleanDataItem = {
    dataType: ItemDataType.Boolean
    value: boolean
}
type INT8DataItem = {
    dataType: ItemDataType.INT8
    value: number
}
type INT16DataItem = {
    dataType: ItemDataType.INT16
    value: number
}
type INT32DataItem = {
    dataType: ItemDataType.INT32
    value: number
}
type INT64DataItem = {
    dataType: ItemDataType.INT64
    value: bigint
}
type INT8UDataItem = {
    dataType: ItemDataType.INT8U
    value: number
}
type INT16UDataItem = {
    dataType: ItemDataType.INT16U
    value: number
}
type INT32UDataItem = {
    dataType: ItemDataType.INT32U
    value: number
}
type FLOAT32DataItem = {
    dataType: ItemDataType.FLOAT32
    value: number
}
type CODEDENUMDataItem = {
    dataType: ItemDataType.CODEDENUM
    value: number
}
type OCTETSTRINGDataItem = {
    dataType: ItemDataType.OCTETSTRING
    value: string
}
type VISIBLESTRINGDataItem = {
    dataType: ItemDataType.VISIBLESTRING
    value: string
}
type TimeStampDataItem = {
    dataType: ItemDataType.TimeStamp
    value: string
}
type QualityDataItem = {
    dataType: ItemDataType.Quality
    value: string
}
type StructureDataItem = {
    dataType: ItemDataType.Structure
    value: DataItem[]
}

type DataItem = BooleanDataItem |
    INT8DataItem |
    INT16DataItem |
    INT32DataItem |
    INT64DataItem |
    INT8UDataItem |
    INT16UDataItem |
    INT32UDataItem |
    FLOAT32DataItem |
    CODEDENUMDataItem |
    OCTETSTRINGDataItem |
    VISIBLESTRINGDataItem |
    TimeStampDataItem |
    QualityDataItem |
    StructureDataItem

export class Goose extends BaseHeader {

    protected TLVInstance: TLV

    protected TLVChild: TLV[] = []

    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            appid: {
                type: 'integer',
                minimum: 0,
                maximum: 65535,
                label: 'APPID',
                decode: (): void => {
                    this.instance.appid.setValue(BufferToUInt16(this.readBytes(0, 2)))
                },
                encode: (): void => {
                    const APPID: number = this.instance.appid.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.appid.setValue(APPID)
                    this.writeBytes(0, UInt16ToBuffer(APPID))
                }
            },
            length: {
                type: 'integer',
                minimum: 0,
                maximum: 65535,
                label: 'Length',
                decode: (): void => {
                    this.instance.length.setValue(BufferToUInt16(this.readBytes(2, 2)))
                },
                encode: (): void => {
                    const length: number = this.instance.length.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    if (length > 0) {
                        this.instance.length.setValue(length)
                        this.writeBytes(2, UInt16ToBuffer(length))
                    } else {
                        this.addPostSelfEncodeHandler((): void => {
                            const finalLength: number = parseInt(this.instance.length.getValue().toString())
                            this.writeBytes(2, UInt16ToBuffer(finalLength))
                        })
                    }
                }
            },
            reserved1: {
                type: 'object',
                label: 'Reserved1',
                properties: {
                    simulated: {
                        type: 'boolean',
                        label: 'Simulated',
                        decode: (): void => {
                            this.instance.reserved1.simulated.setValue(!!this.readBits(4, 2, 0, 1))
                        },
                        encode: (): void => {
                            const simulated: boolean = this.instance.reserved1.simulated.getValue(false)
                            this.writeBits(4, 2, 0, 1, simulated ? 1 : 0)
                        }
                    },
                    reserved: {
                        type: 'number',
                        minimum: 0,
                        maximum: 32767,
                        label: 'Reserved',
                        decode: (): void => {
                            this.instance.reserved1.reserved.setValue(this.readBits(4, 2, 1, 16))
                        },
                        encode: (): void => {
                            const reserved: number = this.instance.reserved1.reserved.getValue(0)
                            this.writeBits(4, 2, 1, 16, reserved)
                        }
                    }
                }
            },
            reserved2: {
                type: 'object',
                label: 'Reserved2',
                properties: {
                    reserved: {
                        type: 'number',
                        minimum: 0,
                        maximum: 65535,
                        label: 'Reserved',
                        decode: (): void => {
                            this.instance.reserved2.reserved.setValue(this.readBits(4, 2, 0, 16))
                        },
                        encode: (): void => {
                            const reserved: number = this.instance.reserved2.reserved.getValue(0)
                            this.writeBits(4, 2, 0, 16, reserved)
                        }
                    }
                }
            },
            goosePdu: {
                type: 'object',
                label: 'GOOSE PDU',
                decode: (): void => {
                    let readTLVBufferLength: number = this.packet.length - this.startPos - 8
                    while (!this.TLVInstance) {
                        try {
                            const buffer: Buffer = this.readBytes(8, readTLVBufferLength, true)
                            this.TLVInstance = TLV.parse(buffer)
                            const tagWithLength: string[] = buffer.toString('hex').replace(this.TLVInstance.bValue.toString('hex'), '#').split('#')
                            const tagWithLengthBytes: number = Math.max(...tagWithLength.map((value: string): number => Math.ceil(value.length / 2)))
                            const TLVBufferLength: number = this.TLVInstance.bValue.length + tagWithLengthBytes
                            this.TLVInstance = TLV.parse(this.readBytes(8, TLVBufferLength, false))
                        } catch (e) {
                            readTLVBufferLength -= 1
                            if (!readTLVBufferLength) break
                        }
                    }
                    this.TLVChild = this.TLVInstance ? this.TLVInstance.getChild() : []
                },
                encode: (): void => {
                    let buffers: Buffer = Buffer.from([])
                    this.TLVChild.forEach(item => buffers = Buffer.concat([buffers, item.bTag, item.bLength, item.bValue]))
                    const goosePduTLV: TLV = new TLV(0x61, buffers)
                    const goosePduBuffer: Buffer = Buffer.concat([goosePduTLV.bTag, goosePduTLV.bLength, goosePduTLV.bValue])
                    this.writeBytes(8, goosePduBuffer)
                    /**
                     * Update the length only if it is not set
                     * Update length(APPID's length + Length's length + Reserved1's length + Reserved2's length + goosePdu's length)
                     */
                    if (this.instance.length.getValue() > 0) return
                    this.instance.length.setValue(2 + 2 + 2 + 2 + goosePduBuffer.length)
                },
                properties: {
                    gocbRef: {
                        type: 'string',
                        maxLength: 129,
                        label: 'GoCBReference',
                        contentEncoding: StringContentEncodingEnum.ASCII,
                        decode: (): void => {
                            const gocbRefTLV: TLV | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x80)
                            if (!gocbRefTLV) return this.recordError(this.instance.goosePdu.gocbRef.getPath(), 'Not Found')
                            this.instance.goosePdu.gocbRef.setValue(gocbRefTLV.getValue('buffer').toString('ascii'))
                        },
                        encode: (): void => {
                            const gocbRefValue: string = this.instance.goosePdu.gocbRef.getValue('', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (!gocbRefValue) return
                            let gocbRefBuffer: Buffer = Buffer.from(gocbRefValue, 'ascii')
                            if (gocbRefBuffer.length > 129) {
                                this.recordError(this.instance.goosePdu.gocbRef.getPath(), 'This VisibleString shall have a maximum size of 129 octets')
                                gocbRefBuffer = gocbRefBuffer.subarray(0, 129)
                            }
                            this.TLVChild.push(new TLV(0x80, gocbRefBuffer))
                        }
                    },
                    timeAllowedtoLive: {
                        type: 'number',
                        minimum: 0,
                        maximum: 4294967295,
                        label: 'TimeAllowedtoLive',
                        decode: (): void => {
                            const timeAllowedtoLiveString: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x81)?.getValue('hex')
                            if (!timeAllowedtoLiveString) return this.recordError(this.instance.goosePdu.timeAllowedtoLive.getPath(), 'Not Found')
                            this.instance.goosePdu.timeAllowedtoLive.setValue(HexToUInt32(timeAllowedtoLiveString))
                        },
                        encode: (): void => {
                            let timeAllowedtoLiveValue: number = this.instance.goosePdu.timeAllowedtoLive.getValue(-1, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (timeAllowedtoLiveValue === -1) return
                            if (timeAllowedtoLiveValue < 1 || timeAllowedtoLiveValue > 4294967295) {
                                this.recordError(this.instance.goosePdu.timeAllowedtoLive.getPath(), 'This INTEGER value shall have a range of 1 to 4294967295')
                                timeAllowedtoLiveValue = 4294967295
                            }
                            const timeAllowedtoLiveTLV: TLV = new TLV(0x81, UInt32ToBERBuffer(timeAllowedtoLiveValue))
                            this.TLVChild.push(timeAllowedtoLiveTLV)
                        }
                    },
                    datSet: {
                        type: 'string',
                        maxLength: 129,
                        label: 'DatSet',
                        contentEncoding: StringContentEncodingEnum.ASCII,
                        decode: (): void => {
                            const datSetTLV: TLV | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x82)
                            if (!datSetTLV) return this.recordError(this.instance.goosePdu.datSet.getPath(), 'Not Found')
                            this.instance.goosePdu.datSet.setValue(datSetTLV.getValue('buffer').toString('ascii'))
                        },
                        encode: (): void => {
                            const datSetValue: string = this.instance.goosePdu.datSet.getValue('', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (!datSetValue) return
                            let datSetBuffer: Buffer = Buffer.from(datSetValue, 'ascii')
                            if (datSetBuffer.length > 129) {
                                this.recordError(this.instance.goosePdu.datSet.getPath(), 'This VisibleString shall have a maximum size of 129 octets')
                                datSetBuffer = datSetBuffer.subarray(0, 129)
                            }
                            this.TLVChild.push(new TLV(0x82, datSetBuffer))
                        }
                    },
                    goID: {
                        type: 'string',
                        maxLength: 65,
                        label: 'GoID',
                        contentEncoding: StringContentEncodingEnum.ASCII,
                        decode: (): void => {
                            const goIDTLV: TLV | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x83)
                            if (!goIDTLV) return this.recordError(this.instance.goosePdu.goID.getPath(), 'Not Found')
                            this.instance.goosePdu.goID.setValue(goIDTLV.getValue('buffer').toString('ascii'))
                        },
                        encode: (): void => {
                            const goIDValue: string = this.instance.goosePdu.goID.getValue('', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (!goIDValue) return
                            let goIDBuffer: Buffer = Buffer.from(goIDValue, 'ascii')
                            if (goIDBuffer.length > 65) {
                                this.recordError(this.instance.goosePdu.goID.getPath(), 'This VisibleString shall have a maximum size of 65 octets')
                                goIDBuffer = goIDBuffer.subarray(0, 65)
                            }
                            this.TLVChild.push(new TLV(0x83, goIDBuffer))
                        }
                    },
                    t: {
                        type: 'string',
                        label: 'TimeStamp',
                        contentEncoding: StringContentEncodingEnum.BIGINT,
                        decode: (): void => {
                            const tStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x84)?.getValue('hex')
                            if (!tStr) return this.recordError(this.instance.goosePdu.t.getPath(), 'Not Found')
                            this.instance.goosePdu.t.setValue(BigInt(`0x${tStr}`).toString())
                        },
                        encode: (): void => {
                            const tStr: string = this.instance.goosePdu.t.getValue('', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (!tStr) return
                            const tBigIntValue: bigint = BigInt(tStr)
                            const tTLV: TLV = new TLV(0x84, Buffer.from(tBigIntValue.toString(16).padStart(8 * 2, '0'), 'hex'))
                            this.TLVChild.push(tTLV)
                        }
                    },
                    stNum: {
                        type: 'integer',
                        minimum: 0,
                        maximum: 4294967295,
                        label: 'StNum',
                        decode: (): void => {
                            const stNumStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x85)?.getValue('hex')
                            if (!stNumStr) return this.recordError(this.instance.goosePdu.stNum.getPath(), 'Not Found')
                            this.instance.goosePdu.stNum.setValue(HexToUInt32(stNumStr))
                            if (this.instance.goosePdu.stNum.getValue() < 1 || this.instance.goosePdu.stNum.getValue() > 4294967295) this.recordError(this.instance.goosePdu.stNum.getPath(), 'This INTEGER value shall have a range of 1 to 4294967295')
                        },
                        encode: (): void => {
                            let stNumValue: number = this.instance.goosePdu.stNum.getValue(-1, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (stNumValue < 0) return
                            if (stNumValue > 4294967295) {
                                stNumValue = 4294967295
                                this.recordError(this.instance.goosePdu.stNum.getPath(), 'This INTEGER value shall have a range of 1 to 4294967295')
                            }
                            if (stNumValue === undefined) return this.recordError(this.instance.goosePdu.stNum.getPath(), 'Not Found')
                            const stNumTLV: TLV = new TLV(0x85, UInt32ToBERBuffer(stNumValue))
                            this.TLVChild.push(stNumTLV)
                        }
                    },
                    sqNum: {
                        type: 'integer',
                        minimum: 0,
                        maximum: 4294967295,
                        label: 'SqNum',
                        decode: (): void => {
                            const sqNumStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x86)?.getValue('hex')
                            if (!sqNumStr) return this.recordError(this.instance.goosePdu.sqNum.getPath(), 'Not Found')
                            this.instance.goosePdu.sqNum.setValue(HexToUInt32(sqNumStr))
                        },
                        encode: (): void => {
                            let sqNumValue: number = this.instance.goosePdu.sqNum.getValue(-1, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (sqNumValue < 0) return
                            if (sqNumValue > 4294967295) {
                                sqNumValue = 4294967295
                                this.recordError(this.instance.goosePdu.sqNum.getPath(), 'This INTEGER value shall have a range of 1 to 4294967295')
                            }
                            if (sqNumValue === undefined) return this.recordError(this.instance.goosePdu.sqNum.getPath(), 'Not Found')
                            const sqNumTLV: TLV = new TLV(0x86, UInt32ToBERBuffer(sqNumValue))
                            this.TLVChild.push(sqNumTLV)
                        }
                    },
                    simulation: {
                        type: 'boolean',
                        label: 'Simulation',
                        decode: (): void => {
                            const simulationStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x87)?.getValue('hex')
                            if (!simulationStr) return this.recordError(this.instance.goosePdu.simulation.getPath(), 'Not Found')
                            const simulationNum: number = parseInt(simulationStr, 16)
                            if (simulationNum > 1) this.recordError(this.instance.goosePdu.simulation.getPath(), 'This Boolean shall have a range of TRUE, FALSE')
                            this.instance.goosePdu.simulation.setValue(!!simulationNum)
                        },
                        encode: (): void => {
                            const simulationValue: boolean | undefined = this.instance.goosePdu.simulation.getValue(undefined, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (simulationValue === undefined) return
                            const simulationNum: number = simulationValue ? 1 : 0
                            const simulationTLV: TLV = new TLV(0x87, Buffer.from(simulationNum.toString(16).padStart(2, '0'), 'hex'))
                            this.TLVChild.push(simulationTLV)
                        }
                    },
                    confRev: {
                        type: 'integer',
                        label: 'ConfRev',
                        decode: (): void => {
                            const confRevStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x88)?.getValue('hex')
                            if (!confRevStr) return this.recordError(this.instance.goosePdu.confRev.getPath(), 'Not Found')
                            this.instance.goosePdu.confRev.setValue(HexToUInt32(confRevStr))
                        },
                        encode: (): void => {
                            let confRevValue: number = this.instance.goosePdu.confRev.getValue(-1, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (confRevValue > 4294967295) {
                                confRevValue = 4294967295
                                this.recordError(this.instance.goosePdu.confRev.getPath(), 'This INTEGER value shall have a range of 0 to 4294967295')
                            }
                            if (confRevValue === -1) return
                            const confRevTLV: TLV = new TLV(0x88, UInt32ToBERBuffer(confRevValue))
                            this.TLVChild.push(confRevTLV)
                        }
                    },
                    ndsCom: {
                        type: 'boolean',
                        label: 'NdsCom',
                        decode: (): void => {
                            const ndsComStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x89)?.getValue('hex')
                            if (!ndsComStr) return this.recordError(this.instance.goosePdu.ndsCom.getPath(), 'Not Found')
                            const ndsComNum: number = parseInt(ndsComStr, 16)
                            if (ndsComNum > 1) this.recordError(this.instance.goosePdu.ndsCom.getPath(), 'This Boolean shall have a range of TRUE, FALSE')
                            this.instance.goosePdu.ndsCom.setValue(!!ndsComNum)
                        },
                        encode: (): void => {
                            const ndsComValue: boolean | undefined = this.instance.goosePdu.ndsCom.getValue(undefined, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (ndsComValue === undefined) return
                            const ndsComNum: number = ndsComValue ? 1 : 0
                            const ndsComTLV: TLV = new TLV(0x89, Buffer.from(ndsComNum.toString(16).padStart(2, '0'), 'hex'))
                            this.TLVChild.push(ndsComTLV)
                        }
                    },
                    numDatSetEntries: {
                        type: 'integer',
                        label: 'NumDatSetEntries',
                        decode: (): void => {
                            const numDatSetEntriesStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x8A)?.getValue('hex')
                            if (!numDatSetEntriesStr) return this.recordError(this.instance.goosePdu.numDatSetEntries.getPath(), 'Not Found')
                            this.instance.goosePdu.numDatSetEntries.setValue(parseInt(numDatSetEntriesStr, 16))
                        },
                        encode: (): void => {
                            const numDatSetEntriesValue: number | undefined = this.instance.goosePdu.numDatSetEntries.getValue(undefined, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (numDatSetEntriesValue === undefined) return
                            const numDatSetEntriesTLV: TLV = new TLV(0x8A, UInt32ToBERBuffer(numDatSetEntriesValue))
                            this.TLVChild.push(numDatSetEntriesTLV)
                        }
                    },
                    allData: {
                        type: 'array',
                        label: 'AllData',
                        items: {
                            anyOf: [
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.Boolean]},
                                        value: {type: 'boolean'}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.INT8]},
                                        value: {type: 'integer'}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.INT16]},
                                        value: {type: 'integer'}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.INT32]},
                                        value: {type: 'integer'}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.INT64]},
                                        value: {type: 'string', contentEncoding: StringContentEncodingEnum.BIGINT}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.INT8U]},
                                        value: {type: 'integer'}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.INT16U]},
                                        value: {type: 'integer'}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.INT32U]},
                                        value: {type: 'integer'}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.FLOAT32]},
                                        value: {type: 'number'}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.CODEDENUM]},
                                        value: {type: 'integer'}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.OCTETSTRING]},
                                        value: {type: 'string', contentEncoding: StringContentEncodingEnum.HEX}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.VISIBLESTRING]},
                                        value: {type: 'string', contentEncoding: StringContentEncodingEnum.ASCII}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.TimeStamp]},
                                        value: {type: 'string'}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.Quality]},
                                        value: {type: 'string', contentEncoding: StringContentEncodingEnum.BINARY}
                                    }
                                },
                                {
                                    type: 'object',
                                    properties: {
                                        dataType: {type: 'string', enum: [ItemDataType.Structure]},
                                        value: {
                                            type: 'array',
                                            $ref: '#/properties/goosePdu/properties/allData'
                                        }
                                    }
                                }
                            ]
                        },
                        /**
                         * +-----------------------------------+-------------------+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+
                         * | Data types according to IEC 61850-7-2 | ASN.1 Tag for Data | ASN.1 Length      | Comments                                                                                                                                           |
                         * +-----------------------------------+-------------------+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+
                         * | Boolean                               | 0x83               |         1         | 8 Bit set to 0 FALSE; anything else = TRUE                                                                                                         |
                         * | INT8                                  | 0x85               |         2         | 8 Bit Big Endian; signed                                                                                                                           |
                         * | INT16                                 | 0x85               |         3         | 16 Bit Big Endian; signed                                                                                                                          |
                         * | INT32                                 | 0x85               |         5         | 32 Bit Big Endian; signed                                                                                                                          |
                         * | INT64                                 | 0x85               |         9         | 64Bit Big Endian; signed                                                                                                                           |
                         * | INT8U                                 | 0x86               |         2         | 8 Bit Big Endian; unsigned                                                                                                                         |
                         * | INT16U                                | 0x86               |         3         | 16 Bit Big Endian; unsigned                                                                                                                        |
                         * | INT24U                                | -                  |         -         | Not used                                                                                                                                           |
                         * | INT32U                                | 0x86               |         5         | 32 Bit Big Endian; unsigned                                                                                                                        |
                         * | FLOAT32                               | 0x87               |         4         | 32 Bit IEEE Floating Point (IEEE 754)                                                                                                              |
                         * | CODED-ENUM                            | 0x84               |         2         | Bit-string; depending on CODED ENUM definition – most of the time, can be encoded with 2 bytes (1st Byte = number of unused bit, 2nd Byte = Value) |
                         * | OCTET-STRING                          | 0x89               |         20        | 20 Bytes ASCII Text, Null terminated                                                                                                               |
                         * | VISIBLE-STRING                        | 0x8a               |         35        | 35 Bytes ASCII Text, Null terminated                                                                                                               |
                         * | TimeStamp                             | 0x91               |         8         | 64 Bit TimeStamp as defined in 8.1.3.7 IEC 6                                                                                                       |
                         * | Quality                               | 0x84               |         3         | Bit-string                                                                                                                                         |
                         * +-----------------------------------+-------------------+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+
                         */
                        decode: (): void => {
                            const allDataTLV: TLV | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0xAB)
                            const dataTLVs: TLV[] = allDataTLV ? allDataTLV.getChild() : []
                            const allData: DataItem[] = this.decodeDataTLVItem(dataTLVs)
                            if (allData.length) this.instance.goosePdu.allData.setValue(allData)
                        },
                        encode: (): void => {
                            const allData: DataItem[] = this.instance.goosePdu.allData.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            const dataItemTLVs: TLV[] = this.encodeDataTLVItem(allData)
                            if (dataItemTLVs.length) {
                                const allDataTLV: TLV = new TLV(0xAB, Buffer.concat(dataItemTLVs.map((dataItemTLV: TLV): Buffer => Buffer.concat([dataItemTLV.bTag, dataItemTLV.bLength, dataItemTLV.bValue]))))
                                this.TLVChild.push(allDataTLV)
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Decode data TLV items
     * @param dataTLVs
     * @protected
     */
    protected decodeDataTLVItem(dataTLVs: TLV[]): DataItem[] {
        const dataItems: DataItem[] = []
        dataTLVs.forEach((dataTLV: TLV): void => {
            const length: number = dataTLV.getLength('number')
            const value: Buffer = dataTLV.getValue('buffer')
            switch (dataTLV.getTag('number')) {
                case 0x83: {
                    dataItems.push({
                        dataType: ItemDataType.Boolean,
                        value: !!parseInt(value.toString('hex'), 16)
                    })
                }
                    break
                case 0x84: {
                    switch (length) {
                        case 2: {
                            dataItems.push({
                                dataType: ItemDataType.CODEDENUM,
                                value: parseInt(value.toString('hex'), 16)
                            })
                        }
                            break
                        case 3: {
                            dataItems.push({
                                dataType: ItemDataType.Quality,
                                value: parseInt(value.toString('hex'), 16).toString(2).padStart(24, '0')
                            })
                        }
                            break
                    }
                }
                    break
                case 0x85: {
                    const integerRealLength: number = GetBERIntegerLengthFromBuffer(value)
                    if (integerRealLength === 1) {
                        dataItems.push({
                            dataType: ItemDataType.INT8,
                            value: HexToInt8(value.toString('hex'))
                        })
                    } else if (integerRealLength === 2) {
                        dataItems.push({
                            dataType: ItemDataType.INT16,
                            value: HexToInt16(value.toString('hex'))
                        })
                    } else if (integerRealLength === 4) {
                        dataItems.push({
                            dataType: ItemDataType.INT32,
                            value: HexToInt32(value.toString('hex'))
                        })
                    } else if (integerRealLength === 8) {
                        dataItems.push({
                            dataType: ItemDataType.INT64,
                            value: HexToInt64(value.toString('hex'))
                        })
                    }
                }
                    break
                case 0x86: {
                    const unsignedIntegerRealLength: number = GetBERIntegerLengthFromBuffer(value)
                    switch (unsignedIntegerRealLength) {
                        case 1: {
                            dataItems.push({
                                dataType: ItemDataType.INT8U,
                                value: HexToUInt8(value.toString('hex'))
                            })
                        }
                            break
                        case 2: {
                            dataItems.push({
                                dataType: ItemDataType.INT16U,
                                value: HexToUInt16(value.toString('hex'))
                            })
                        }
                            break
                        case 4: {
                            dataItems.push({
                                dataType: ItemDataType.INT32U,
                                value: HexToUInt32(value.toString('hex'))
                            })
                        }
                            break
                    }
                }
                    break
                case 0x87: {
                    dataItems.push({
                        dataType: ItemDataType.FLOAT32,
                        value: HexToFloat32(value.toString('hex'))
                    })
                }
                    break
                case 0x89: {
                    dataItems.push({
                        dataType: ItemDataType.OCTETSTRING,
                        value: value.toString('hex')
                    })
                }
                    break
                case 0x8a: {
                    dataItems.push({
                        dataType: ItemDataType.VISIBLESTRING,
                        value: value.toString('ascii')
                    })
                }
                    break
                case 0x91: {
                    dataItems.push({
                        dataType: ItemDataType.TimeStamp,
                        value: parseInt(value.toString('hex'), 16).toString()
                    })
                }
                    break
                case 0xa2: {
                    const subDataTLVs: TLV[] = TLV.parseList(value)
                    dataItems.push({
                        dataType: ItemDataType.Structure,
                        value: this.decodeDataTLVItem(subDataTLVs)
                    })
                }
                    break
            }
        })
        return dataItems
    }

    /**
     * Encode data TLV items
     * @param dataItems
     * @protected
     */
    protected encodeDataTLVItem(dataItems: DataItem[]): TLV[] {
        return dataItems
            .map((dataItem: DataItem, index: number): TLV | null => {
                const errorNodePath: string = this.instance.goosePdu.allData.getPath(index)
                switch (dataItem.dataType) {
                    case ItemDataType.Boolean: {
                        const booleanIntValue: number = dataItem.value ? 1 : 0
                        return new TLV(0x83, Buffer.from(booleanIntValue.toString(16).padStart(2, '0'), 'hex'))
                    }
                    case ItemDataType.INT8: {
                        let intValue: number = dataItem.value
                        if (isNaN(intValue)) this.recordError(errorNodePath, 'Invalid INT8 value')
                        intValue = intValue ? intValue : 0
                        if (intValue < -128 || intValue > 127) this.recordError(errorNodePath, 'Invalid INT8 value')
                        return new TLV(0x85, Buffer.from(Int8ToBERHex(intValue), 'hex'))
                    }
                    case ItemDataType.INT16: {
                        let intValue: number = dataItem.value
                        if (isNaN(intValue)) this.recordError(errorNodePath, 'Invalid INT16 value')
                        intValue = intValue ? intValue : 0
                        if (intValue < -32768 || intValue > 32767) this.recordError(errorNodePath, 'Invalid INT16 value')
                        return new TLV(0x85, Buffer.from(Int16ToBERHex(intValue), 'hex'))
                    }
                    case ItemDataType.INT32: {
                        let intValue: number = dataItem.value
                        if (isNaN(intValue)) this.recordError(errorNodePath, 'Invalid INT32 value')
                        intValue = intValue ? intValue : 0
                        if (intValue < -2147483648 || intValue > 2147483647) this.recordError(errorNodePath, 'Invalid INT32 value')
                        return new TLV(0x85, Buffer.from(Int32ToBERHex(intValue), 'hex'))
                    }
                    case ItemDataType.INT64: {
                        const intValue: bigint = BigInt(dataItem.value)
                        if (intValue < BigInt('-9223372036854775808') || intValue > BigInt('9223372036854775807')) this.recordError(errorNodePath, 'Invalid INT64 value')
                        return new TLV(0x85, Buffer.from(Int64ToBERHex(intValue), 'hex'))
                    }
                    case ItemDataType.INT8U: {
                        let uintValue: number = dataItem.value
                        if (isNaN(uintValue)) this.recordError(errorNodePath, 'Invalid INT8U value')
                        uintValue = uintValue ? uintValue : 0
                        if (uintValue < 0 || uintValue > 255) this.recordError(errorNodePath, 'Invalid INT8U value')
                        return new TLV(0x86, Buffer.from(UInt8ToBERHex(uintValue), 'hex'))
                    }
                    case ItemDataType.INT16U: {
                        let uintValue: number = dataItem.value
                        if (isNaN(uintValue)) this.recordError(errorNodePath, 'Invalid INT16U value')
                        uintValue = uintValue ? uintValue : 0
                        if (uintValue < 0 || uintValue > 65535) this.recordError(errorNodePath, 'Invalid INT16U value')
                        return new TLV(0x86, Buffer.from(UInt16ToBERHex(uintValue), 'hex'))
                    }
                    case ItemDataType.INT32U: {
                        let uintValue: number = dataItem.value
                        if (isNaN(uintValue)) this.recordError(errorNodePath, 'Invalid INT32U value')
                        uintValue = uintValue ? uintValue : 0
                        if (uintValue < 0 || uintValue > 4294967295) this.recordError(errorNodePath, 'Invalid INT32U value')
                        return new TLV(0x86, Buffer.from(UInt32ToBERHex(uintValue), 'hex'))
                    }
                    case ItemDataType.FLOAT32: {
                        let float32Value: number = dataItem.value
                        if (isNaN(float32Value)) this.recordError(errorNodePath, 'Invalid FLOAT32 value')
                        float32Value = float32Value ? float32Value : 0
                        return new TLV(0x87, Buffer.from(Float32ToBERHex(float32Value), 'hex'))
                    }
                    case ItemDataType.CODEDENUM: {
                        let codedEnumValue: number = dataItem.value
                        if (isNaN(codedEnumValue)) this.recordError(errorNodePath, 'Invalid CODED-ENUM value')
                        codedEnumValue = codedEnumValue ? codedEnumValue : 0
                        return new TLV(0x84, Buffer.from(UInt16ToBERHex(codedEnumValue), 'hex'))
                    }
                    case ItemDataType.OCTETSTRING: {
                        const hexText: string = dataItem.value
                        if (!hexText) {
                            this.recordError(errorNodePath, 'Empty OCTET-STRING, ignored')
                            return null
                        }
                        if (hexText.length > 20) this.recordError(errorNodePath, 'OCTET-STRING too long')
                        return new TLV(0x89, Buffer.from(hexText, 'hex').subarray(0, 20))
                    }
                    case ItemDataType.VISIBLESTRING: {
                        const asciiText: string = dataItem.value
                        if (!asciiText) {
                            this.recordError(errorNodePath, 'Empty VISIBLE-STRING, ignored')
                            return null
                        }
                        if (asciiText.length > 35) this.recordError(errorNodePath, 'VISIBLE-STRING too long')
                        const hex: string = Buffer.from(asciiText, 'ascii').toString('hex').padStart(35 * 2)
                        return new TLV(0x8a, Buffer.from(hex, 'hex').subarray(0, 35))
                    }
                    case ItemDataType.TimeStamp: {
                        let timestamp: number = parseInt(dataItem.value)
                        if (isNaN(timestamp)) this.recordError(errorNodePath, 'Invalid TimeStamp value')
                        timestamp = timestamp ? timestamp : 0
                        return new TLV(0x91, Buffer.from(timestamp.toString(16), 'hex'))
                    }
                    case ItemDataType.Quality: {
                        const bitString: string = dataItem.value
                        let intValue: number = parseInt(bitString, 2)
                        if (isNaN(intValue)) this.recordError(errorNodePath, 'Invalid Quality value')
                        intValue = intValue ? intValue : 0
                        return new TLV(0x84, Buffer.from(intValue.toString(16).padStart(3 * 2, '0'), 'hex'))
                    }
                    case ItemDataType.Structure: {
                        return new TLV(0xa2, Buffer.concat(this.encodeDataTLVItem(dataItem.value).map((tlv: TLV): Buffer => Buffer.concat([tlv.bTag, tlv.bLength, tlv.bValue]))))
                    }
                    default: {
                        this.recordError(errorNodePath, 'Invalid dataType, ignored')
                        return null
                    }
                }
            })
            .filter((value: TLV | null): value is TLV => !!value)
    }

    public readonly id: string = 'goose'

    public readonly name: string = 'IEC61850 GOOSE'

    public readonly nickname: string = 'GOOSE'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.etherType.getValue() === UInt16ToHex(0x88b8)
    }
}
