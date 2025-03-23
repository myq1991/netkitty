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
} from '../lib/HexToNumber'
import {
    Int16ToBERHex,
    Int32ToBERHex,
    Int64ToBERHex,
    Int8ToBERHex,
    UInt16ToBERHex,
    UInt32ToBERHex,
    UInt8ToBERHex
} from '../lib/NumberToBERHex'
import {Float32ToHex, UInt16ToHex} from '../lib/NumberToHex'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {UInt32ToBERBuffer} from '../lib/NumberToBERBuffer'

type AllDataItem = {
    dataType: string
    value: string
}

export default class Goose extends BaseHeader {

    protected TLVInstance: TLV

    protected TLVChild: TLV[] = []

    public SCHEMA: ProtocolJSONSchema = {
        properties: {
            appid: {
                type: 'integer',
                minimum: 0,
                maximum: 0x3fff,
                label: 'APPID',
                decode: (): void => {
                    this.instance.appid.setValue(parseInt(this.readBytes(0, 2).toString('hex'), 16))
                },
                encode: (): void => {
                    let APPID: number = parseInt(this.instance.appid.getValue().toString())
                    APPID = APPID ? APPID : 0
                    this.writeBytes(0, Buffer.from(APPID.toString(16).padStart(4, '0'), 'hex'))
                }
            },
            length: {
                type: 'integer',
                minimum: 0,
                maximum: 65535,
                label: 'Length',
                decode: (): void => {
                    this.instance.length.setValue(parseInt(this.readBytes(2, 2).toString('hex'), 16))
                    if (this.instance.length.isUndefined()) this.recordError('length', 'Not Found')
                },
                encode: (): void => {
                    let length: number = parseInt(this.instance.length.getValue().toString())
                    length = length ? length : 0
                    if (length > 0) {
                        this.writeBytes(2, Buffer.from(length.toString(16).padStart(4, '0'), 'hex'))
                    } else {
                        this.addPostSelfEncodeHandler((): void => {
                            let finalLength: number = parseInt(this.instance.length.getValue().toString())
                            this.writeBytes(2, Buffer.from(finalLength.toString(16).padStart(4, '0'), 'hex'))
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
                            const simulated: boolean = !!this.instance.reserved1.simulated.getValue()
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
                            let reserved: number = parseInt(this.instance.reserved1.reserved.getValue().toString())
                            reserved = reserved ? reserved : 0
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
                            let reserved: number = parseInt(this.instance.reserved2.reserved.getValue().toString())
                            reserved = reserved ? reserved : 0
                            this.writeBits(4, 2, 0, 16, reserved)
                        }
                    }
                }
            },
            goosePdu: {
                type: 'object',
                label: 'GOOSE PDU',
                decode: (): void => {
                    const buffer: Buffer = this.readBytes(8, (this.instance.length.getValue() as number) - 8)
                    this.TLVInstance = TLV.parse(buffer)
                    this.TLVChild = this.TLVInstance.getChild()
                    this.instance.goosePdu.setValue({})
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
                            if (!gocbRefTLV) return this.recordError('goosePdu.gocbRef', 'Not Found')
                            this.instance.goosePdu.gocbRef.setValue(gocbRefTLV.getValue('buffer').toString('ascii'))
                        },
                        encode: (): void => {
                            const gocbRefValue: string = this.instance.goosePdu.gocbRef.getValue()
                            if (!gocbRefValue) return this.recordError('goosePdu.gocbRef', 'Not Found')
                            let gocbRefBuffer: Buffer = Buffer.from(gocbRefValue, 'ascii')
                            if (gocbRefBuffer.length > 129) {
                                this.recordError('goosePdu.gocbRef', 'This VisibleString shall have a maximum size of 129 octets')
                                gocbRefBuffer = gocbRefBuffer.subarray(0, 129)
                            }
                            this.TLVChild.push(new TLV(0x80, gocbRefBuffer))
                        }
                    },
                    timeAllowedtoLive: {
                        type: 'number',
                        minimum: 1,
                        maximum: 4294967295,
                        label: 'TimeAllowedtoLive',
                        decode: (): void => {
                            const timeAllowedtoLiveString: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x81)?.getValue('hex')
                            if (!timeAllowedtoLiveString) return this.recordError('goosePdu.timeAllowedtoLive', 'Not Found')
                            this.instance.goosePdu.timeAllowedtoLive.setValue(HexToUInt32(timeAllowedtoLiveString))
                        },
                        encode: (): void => {
                            let timeAllowedtoLiveValue: number = this.instance.goosePdu.timeAllowedtoLive.getValue()
                            if (timeAllowedtoLiveValue === undefined) return this.recordError('goosePdu.timeAllowedtoLive', 'Not Found')
                            if (timeAllowedtoLiveValue < 1 || timeAllowedtoLiveValue > 4294967295) {
                                this.recordError('goosePdu.timeAllowedtoLive', 'This INTEGER value shall have a range of 1 to 4294967295')
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
                            if (!datSetTLV) return this.recordError('goosePdu.datSet', 'Not Found')
                            this.instance.goosePdu.datSet.setValue(datSetTLV.getValue('buffer').toString('ascii'))
                        },
                        encode: (): void => {
                            const datSetValue: string = this.instance.goosePdu.datSet.getValue()
                            if (!datSetValue) return this.recordError('goosePdu.datSet', 'Not Found')
                            let datSetBuffer: Buffer = Buffer.from(datSetValue, 'ascii')
                            if (datSetBuffer.length > 129) {
                                this.recordError('goosePdu.datSet', 'This VisibleString shall have a maximum size of 129 octets')
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
                            if (!goIDTLV) return this.recordError('goosePdu.goID', 'Not Found')
                            this.instance.goosePdu.goID.setValue(goIDTLV.getValue('buffer').toString('ascii'))
                        },
                        encode: (): void => {
                            const goIDValue: string = this.instance.goosePdu.goID.getValue()
                            if (!goIDValue) return this.recordError('goosePdu.goID', 'Not Found')
                            let goIDBuffer: Buffer = Buffer.from(goIDValue, 'ascii')
                            if (goIDBuffer.length > 65) {
                                this.recordError('goosePdu.goID', 'This VisibleString shall have a maximum size of 65 octets')
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
                            if (!tStr) return this.recordError('goosePdu.t', 'Not Found')
                            this.instance.goosePdu.t.setValue(BigInt(`0x${tStr}`).toString())
                        },
                        encode: (): void => {
                            const tStr: string = this.instance.goosePdu.t.getValue()
                            if (tStr === undefined) return this.recordError('goosePdu.t', 'Not Found')
                            const tBigIntValue: bigint = BigInt(tStr)
                            const tTLV: TLV = new TLV(0x84, Buffer.from(tBigIntValue.toString(16).padStart(8 * 2, '0'), 'hex'))
                            this.TLVChild.push(tTLV)
                        }
                    },
                    stNum: {
                        type: 'integer',
                        minimum: 1,
                        maximum: 4294967295,
                        label: 'StNum',
                        decode: (): void => {
                            const stNumStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x85)?.getValue('hex')
                            if (!stNumStr) return this.recordError('goosePdu.stNum', 'Not Found')
                            this.instance.goosePdu.stNum.setValue(HexToUInt32(stNumStr))
                            if (this.instance.goosePdu.stNum.getValue() < 1 || this.instance.goosePdu.stNum.getValue() > 4294967295) this.recordError('goosePdu.stNum', 'This INTEGER value shall have a range of 1 to 4294967295')
                        },
                        encode: (): void => {
                            let stNumValue: number = this.instance.goosePdu.stNum.getValue()
                            if (stNumValue < 1 || stNumValue > 4294967295) {
                                stNumValue = 4294967295
                                this.recordError('goosePdu.stNum', 'This INTEGER value shall have a range of 1 to 4294967295')
                            }
                            if (stNumValue === undefined) return this.recordError('goosePdu.stNum', 'Not Found')
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
                            if (!sqNumStr) return this.recordError('goosePdu.sqNum', 'Not Found')
                            this.instance.goosePdu.sqNum.setValue(HexToUInt32(sqNumStr))
                        },
                        encode: (): void => {
                            let sqNumValue: number = this.instance.goosePdu.sqNum.getValue()
                            if (sqNumValue < 0 || sqNumValue > 4294967295) {
                                sqNumValue = 4294967295
                                this.recordError('goosePdu.sqNum', 'This INTEGER value shall have a range of 1 to 4294967295')
                            }
                            if (sqNumValue === undefined) return this.recordError('goosePdu.sqNum', 'Not Found')
                            const sqNumTLV: TLV = new TLV(0x86, UInt32ToBERBuffer(sqNumValue))
                            this.TLVChild.push(sqNumTLV)
                        }
                    },
                    simulation: {
                        type: 'boolean',
                        label: 'Simulation',
                        decode: (): void => {
                            const simulationStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x87)?.getValue('hex')
                            if (!simulationStr) return this.recordError('goosePdu.simulation', 'Not Found')
                            const simulationNum: number = parseInt(simulationStr, 16)
                            if (simulationNum > 1) this.recordError('goosePdu.simulation', 'This Boolean shall have a range of TRUE, FALSE')
                            this.instance.goosePdu.simulation.setValue(!!simulationNum)
                        },
                        encode: (): void => {
                            let simulationValue: boolean | undefined = this.instance.goosePdu.simulation.getValue()
                            if (simulationValue === undefined) return this.recordError('goosePdu.simulation', 'Not Found')
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
                            if (!confRevStr) return this.recordError('goosePdu.confRev', 'Not Found')
                            this.instance.goosePdu.confRev.setValue(HexToUInt32(confRevStr))
                        },
                        encode: (): void => {
                            let confRevValue: number = this.instance.goosePdu.confRev.getValue()
                            if (confRevValue > 4294967295) {
                                confRevValue = 4294967295
                                this.recordError('goosePdu.confRev', 'This INTEGER value shall have a range of 0 to 4294967295')
                            }
                            if (confRevValue === undefined) return this.recordError('goosePdu.confRev', 'Not Found')
                            const confRevTLV: TLV = new TLV(0x88, UInt32ToBERBuffer(confRevValue))
                            this.TLVChild.push(confRevTLV)
                        }
                    },
                    ndsCom: {
                        type: 'boolean',
                        label: 'NdsCom',
                        decode: (): void => {
                            const ndsComStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x89)?.getValue('hex')
                            if (!ndsComStr) return this.recordError('goosePdu.ndsCom', 'Not Found')
                            const ndsComNum: number = parseInt(ndsComStr, 16)
                            if (ndsComNum > 1) this.recordError('goosePdu.ndsCom', 'This Boolean shall have a range of TRUE, FALSE')
                            this.instance.goosePdu.ndsCom.setValue(!!ndsComNum)
                        },
                        encode: (): void => {
                            let ndsComValue: boolean | undefined = this.instance.goosePdu.ndsCom.getValue()
                            if (ndsComValue === undefined) return this.recordError('goosePdu.ndsCom', 'Not Found')
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
                            if (!numDatSetEntriesStr) return this.recordError('goosePdu.numDatSetEntries', 'Not Found')
                            this.instance.goosePdu.numDatSetEntries.setValue(parseInt(numDatSetEntriesStr, 16))
                        },
                        encode: (): void => {
                            let numDatSetEntriesValue: number | undefined = this.instance.goosePdu.numDatSetEntries.getValue()
                            if (numDatSetEntriesValue === undefined) return this.recordError('goosePdu.numDatSetEntries', 'Not Found')
                            const numDatSetEntriesTLV: TLV = new TLV(0x8A, UInt32ToBERBuffer(numDatSetEntriesValue))
                            this.TLVChild.push(numDatSetEntriesTLV)
                        }
                    },
                    allData: {
                        type: 'array',
                        label: 'AllData',
                        items: {
                            type: 'object',
                            label: 'Data',
                            properties: {
                                dataType: {
                                    type: 'string',
                                    label: 'DataType',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [
                                        'Boolean',
                                        'INT8',
                                        'INT16',
                                        'INT32',
                                        'INT64',
                                        'INT8U',
                                        'INT16U',
                                        'INT32U',
                                        'FLOAT32',
                                        'CODED-ENUM',
                                        'OCTET-STRING',
                                        'VISIBLE-STRING',
                                        'TimeStamp',
                                        'Quality'
                                    ]
                                },
                                value: {
                                    type: 'string',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    label: 'Value'
                                }
                            }
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
                            const allData: AllDataItem[] = []
                            dataTLVs.forEach((dataTLV: TLV): void => {
                                const length: number = dataTLV.getLength('number')
                                const value: Buffer = dataTLV.getValue('buffer')
                                const dataItem: AllDataItem = {
                                    dataType: '',
                                    value: ''
                                }
                                switch (dataTLV.getTag('number')) {
                                    case 0x83: {
                                        dataItem.dataType = 'Boolean'
                                        dataItem.value = String(!!parseInt(value.toString('hex'), 16))
                                    }
                                        break
                                    case 0x84: {
                                        switch (length) {
                                            case 2: {
                                                dataItem.dataType = 'CODED-ENUM'
                                                dataItem.value = parseInt(value.toString('hex'), 16).toString()
                                            }
                                                break
                                            case 3: {
                                                dataItem.dataType = 'Quality'
                                                dataItem.value = parseInt(value.toString('hex'), 16).toString(2).padStart(24, '0')
                                            }
                                                break
                                        }
                                    }
                                        break
                                    case 0x85: {
                                        if (length === 2) {
                                            {
                                                dataItem.dataType = 'INT8'
                                                dataItem.value = HexToInt8(value.toString('hex')).toString()
                                            }
                                        } else if (length === 3) {
                                            {
                                                dataItem.dataType = 'INT16'
                                                dataItem.value = HexToInt16(value.toString('hex')).toString()
                                            }
                                        } else if (length === 5) {
                                            {
                                                dataItem.dataType = 'INT32'
                                                dataItem.value = HexToInt32(value.toString('hex')).toString()
                                            }
                                        } else if (length === 9) {
                                            {
                                                dataItem.dataType = 'INT64'
                                                dataItem.value = HexToInt64(value.toString('hex')).toString()
                                            }
                                        }
                                    }
                                        break
                                    case 0x86: {
                                        switch (length) {
                                            case 2: {
                                                dataItem.dataType = 'INT8U'
                                                dataItem.value = HexToUInt8(value.toString('hex')).toString()
                                            }
                                                break
                                            case 3: {
                                                dataItem.dataType = 'INT16U'
                                                dataItem.value = HexToUInt16(value.toString('hex')).toString()
                                            }
                                                break
                                            case 5: {
                                                dataItem.dataType = 'INT32U'
                                                dataItem.value = HexToUInt32(value.toString('hex')).toString()
                                            }
                                                break
                                        }
                                    }
                                        break
                                    case 0x87: {
                                        dataItem.dataType = 'FLOAT32'
                                        dataItem.value = HexToFloat32(value.toString('hex')).toString()
                                    }
                                        break
                                    case 0x89: {
                                        dataItem.dataType = 'OCTET-STRING'
                                        dataItem.value = value.toString('ascii')
                                    }
                                        break
                                    case 0x8a: {
                                        dataItem.dataType = 'VISIBLE-STRING'
                                        dataItem.value = value.toString('ascii')
                                    }
                                        break
                                    case 0x91: {
                                        dataItem.dataType = 'TimeStamp'
                                        dataItem.value = parseInt(value.toString('hex'), 16).toString()
                                    }
                                        break
                                }
                                if (!dataItem.dataType) return
                                allData.push(dataItem)
                            })
                            this.instance.goosePdu.allData.setValue(allData)
                        },
                        encode: (): void => {
                            const allData: AllDataItem[] = this.instance.goosePdu.allData.isUndefined() ? [] : this.instance.goosePdu.allData.getValue()
                            const dataItemTLVs: TLV[] = allData
                                .map((dataItem: AllDataItem, index: number): TLV | null => {
                                    dataItem.value = dataItem.value.trim()
                                    switch (dataItem.dataType) {
                                        case 'Boolean': {
                                            const availableStringValues: string[] = ['FALSE', 'TRUE']
                                            const stringValue: string = dataItem.value.toUpperCase()
                                            let booleanIntValue: number = 0
                                            if (availableStringValues.includes(stringValue)) {
                                                booleanIntValue = availableStringValues.indexOf(stringValue)
                                            } else {
                                                this.recordError(`goosePdu.allData[${index}]`, 'Invalid Boolean value')
                                            }
                                            return new TLV(0x83, Buffer.from(booleanIntValue.toString(16).padStart(2, '0'), 'hex'))
                                        }
                                        case 'INT8': {
                                            let intValue: number = parseInt(dataItem.value)
                                            if (isNaN(intValue)) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT8 value')
                                            intValue = intValue ? intValue : 0
                                            if (intValue < -128 || intValue > 127) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT8 value')
                                            return new TLV(0x85, Buffer.from(Int8ToBERHex(intValue).padStart(2 * 2, '0'), 'hex'))
                                        }
                                        case 'INT16': {
                                            let intValue: number = parseInt(dataItem.value)
                                            if (isNaN(intValue)) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT16 value')
                                            intValue = intValue ? intValue : 0
                                            if (intValue < -32768 || intValue > 32767) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT16 value')
                                            return new TLV(0x85, Buffer.from(Int16ToBERHex(intValue).padStart(3 * 2, '0'), 'hex'))
                                        }
                                        case'INT32': {
                                            let intValue: number = parseInt(dataItem.value)
                                            if (isNaN(intValue)) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT32 value')
                                            intValue = intValue ? intValue : 0
                                            if (intValue < -2147483648 || intValue > 2147483647) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT32 value')
                                            return new TLV(0x85, Buffer.from(Int32ToBERHex(intValue).padStart(5 * 2, '0'), 'hex'))
                                        }
                                        case'INT64': {
                                            let intValue: bigint = BigInt(dataItem.value)
                                            if (intValue < BigInt('-9223372036854775808') || intValue > BigInt('9223372036854775807')) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT64 value')
                                            return new TLV(0x85, Buffer.from(Int64ToBERHex(intValue).padStart(9 * 2, '0'), 'hex'))
                                        }
                                        case'INT8U': {
                                            let uintValue: number = parseInt(dataItem.value)
                                            if (isNaN(uintValue)) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT8U value')
                                            uintValue = uintValue ? uintValue : 0
                                            if (uintValue < 0 || uintValue > 255) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT8U value')
                                            return new TLV(0x86, Buffer.from(UInt8ToBERHex(uintValue).padStart(2 * 2, '0'), 'hex'))
                                        }
                                        case'INT16U': {
                                            let uintValue: number = parseInt(dataItem.value)
                                            if (isNaN(uintValue)) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT16U value')
                                            uintValue = uintValue ? uintValue : 0
                                            if (uintValue < 0 || uintValue > 65535) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT16U value')
                                            return new TLV(0x86, Buffer.from(UInt16ToBERHex(uintValue).padStart(3 * 2, '0'), 'hex'))
                                        }
                                        case'INT32U': {
                                            let uintValue: number = parseInt(dataItem.value)
                                            if (isNaN(uintValue)) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT32U value')
                                            uintValue = uintValue ? uintValue : 0
                                            if (uintValue < 0 || uintValue > 4294967295) this.recordError(`goosePdu.allData[${index}]`, 'Invalid INT32U value')
                                            return new TLV(0x86, Buffer.from(UInt32ToBERHex(uintValue).padStart(5 * 2, '0'), 'hex'))
                                        }
                                        case'FLOAT32': {
                                            let float32Value: number = parseFloat(dataItem.value)
                                            if (isNaN(float32Value)) this.recordError(`goosePdu.allData[${index}]`, 'Invalid FLOAT32 value')
                                            float32Value = float32Value ? float32Value : 0
                                            return new TLV(0x86, Buffer.from(Float32ToHex(float32Value).padStart(4 * 2, '0'), 'hex'))
                                        }
                                        case'CODED-ENUM': {
                                            let codedEnumValue: number = parseInt(dataItem.value)
                                            if (isNaN(codedEnumValue)) this.recordError(`goosePdu.allData[${index}]`, 'Invalid CODED-ENUM value')
                                            codedEnumValue = codedEnumValue ? codedEnumValue : 0
                                            return new TLV(0x84, Buffer.from(UInt16ToBERHex(codedEnumValue).padStart(2 * 2, '0'), 'hex'))
                                        }
                                        case'OCTET-STRING': {
                                            const asciiText: string = dataItem.value
                                            if (!asciiText) {
                                                this.recordError(`goosePdu.allData[${index}]`, 'Empty OCTET-STRING, ignored')
                                                return null
                                            }
                                            if (asciiText.length > 20) this.recordError(`goosePdu.allData[${index}]`, 'OCTET-STRING too long')
                                            const hex: string = Buffer.from(asciiText, 'ascii').toString('hex').padStart(20 * 2)
                                            return new TLV(0x89, Buffer.from(hex, 'hex').subarray(0, 20))
                                        }
                                        case'VISIBLE-STRING': {
                                            const asciiText: string = dataItem.value
                                            if (!asciiText) {
                                                this.recordError(`goosePdu.allData[${index}]`, 'Empty VISIBLE-STRING, ignored')
                                                return null
                                            }
                                            if (asciiText.length > 35) this.recordError(`goosePdu.allData[${index}]`, 'VISIBLE-STRING too long')
                                            const hex: string = Buffer.from(asciiText, 'ascii').toString('hex').padStart(35 * 2)
                                            return new TLV(0x8a, Buffer.from(hex, 'hex').subarray(0, 35))
                                        }
                                        case'TimeStamp': {
                                            let timestamp: number = parseInt(dataItem.value)
                                            if (isNaN(timestamp)) this.recordError(`goosePdu.allData[${index}]`, 'Invalid TimeStamp value')
                                            timestamp = timestamp ? timestamp : 0
                                            return new TLV(0x91, Buffer.from(timestamp.toString(16).padStart(8 * 2, '0'), 'hex'))
                                        }
                                        case'Quality': {
                                            const bitString: string = dataItem.value
                                            let intValue: number = parseInt(bitString, 2)
                                            if (isNaN(intValue)) this.recordError(`goosePdu.allData[${index}]`, 'Invalid Quality value')
                                            intValue = intValue ? intValue : 0
                                            return new TLV(0x84, Buffer.from(intValue.toString(16).padStart(3 * 2, '0'), 'hex'))
                                        }
                                        default: {
                                            this.recordError(`goosePdu.allData[${index}]`, 'Invalid dataType, ignored')
                                            return null
                                        }
                                    }
                                })
                                .filter((dataItemTLV: TLV | null): dataItemTLV is TLV => !!dataItemTLV)

                            let dataItemsHex: string = ''
                            dataItemTLVs.forEach(dataItemTLV => dataItemsHex = `${dataItemsHex}${dataItemTLV.toString()}`)
                            const allDataTLV: TLV = new TLV(0xAB, dataItemsHex)
                            this.TLVChild.push(allDataTLV)
                        }
                    }
                }
            }
        }
    }

    public id: string = 'goose'

    public name: string = 'GOOSE'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.etherType.getValue() === UInt16ToHex(0x88b8)
    }
}
