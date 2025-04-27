import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BufferToUInt32, BufferToUInt16, BufferToUInt8} from '../../helper/BufferToNumber'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BaseHeader} from '../abstracts/BaseHeader'
import {
    Float32ToBuffer,
    Int32ToBuffer,
    UInt16ToBuffer,
    UInt32ToBuffer,
    UInt8ToBuffer
} from '../../helper/NumberToBuffer'


export class IEC104_I_Frame extends BaseHeader {
    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            startByte: {
                type: 'integer',
                label: 'Start Byte',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.startByte.setValue(BufferToUInt8(this.readBytes(0, 1)))
                },
                encode: (): void => {
                    this.writeBytes(0, UInt8ToBuffer(this.instance.startByte.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))))
                }
            },
            apduLength: {
                type: 'integer',
                label: 'APDU Length',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.apduLength.setValue(BufferToUInt8(this.readBytes(1, 1)))
                },
                encode: (): void => {
                    this.writeBytes(1, UInt8ToBuffer(this.instance.apduLength.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))))
                }
            },
            controlField: {
                type: 'string',
                label: 'Control Field',
                decode: (): void => {
                    this.instance.controlField.setValue(BufferToHex(this.readBytes(2, 4)))
                },
                encode: (): void => {
                    this.writeBytes(2, HexToBuffer(this.instance.controlField.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))))
                }
            },
            apciType: {
                type: 'string',
                label: 'APCI Type',
                minimum: 0,
                maximum: 3,
                decode: (): void => {
                    const controlType: number = this.readBits(5, 1, 7, 1)
                    switch (controlType) {
                        case 0: {
                            this.instance.apciType.setValue('I-Format')
                        }
                            break
                        default: {
                            this.recordError(this.instance.apciType.getPath(), 'Illegal acpiType!')
                            this.instance.apciType.setValue(this.readBits(5, 1, 7, 1))
                        }
                    }


                },
                encode: (): void => {
                    const controlType: string = this.instance.apciType.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    switch (controlType) {
                        case 'I-Format': {
                            this.writeBits(5, 1, 7, 1, 0)
                        }
                            break
                        default: {
                            this.writeBits(5, 1, 7, 1, this.instance.apciType.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found')))
                        }
                    }
                }
            },
            messageTypeId: {
                type: 'integer',
                label: 'ASDU Type Identification',
                decode: (): void => {
                    const id: number = BufferToUInt8(this.readBytes(6, 1))
                    if (!(1 <= id && id <= 40 || 45 <= id && id <= 51 || 58 <= id && id <= 64 || id === 70 || 100 <= id && id <= 107 || 110 <= id && id <= 113 || 120 <= id && id <= 127)) {
                        this.recordError(this.instance.messageTypeId.getPath(), 'Unknown messageTypeId')

                    }
                    this.instance.messageTypeId.setValue(id)
                },
                encode: (): void => {
                    const typeId: number = this.instance.messageTypeId.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.writeBytes(6, UInt8ToBuffer(typeId))
                }
            },
            sqBit: {
                type: 'integer',
                label: 'Structure Qualifier Bit',
                minimum: 0,
                maximum: 1,
                decode: (): void => {
                    const bit: number = this.readBits(7, 1, 0, 1)
                    if (!(bit === 1 || bit === 0)) {
                        return this.recordError(this.instance.sqBit.getPath(), 'Illegal value')
                    }
                    this.instance.sqBit.setValue(bit)
                },
                encode: (): void => {
                    const bit: number = this.instance.sqBit.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.writeBits(1, 1, 0, 1, bit)
                }
            },
            numberOfObject: {
                type: 'integer',
                label: 'Number Of Object',
                minimum: 0,
                maximum: 127,
                decode: (): void => {
                    const numberOfObject: number = this.readBits(7, 1, 1, 7)
                    if (!(0 <= numberOfObject && numberOfObject <= 127)) {
                        this.recordError(this.instance.numberOfObject.getPath(), 'Illegal value')
                    }
                    this.instance.numberOfObject.setValue(numberOfObject)
                },
                encode: (): void => {
                    const numberOfObject: number = this.instance.numberOfObject.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.writeBits(7, 1, 1, 7, numberOfObject)
                }
            },
            causeOfTransmission: {
                type: 'integer',
                label: 'Cause Of Transmission',
                minimum: 0,
                maximum: 63,
                decode: (): void => {
                    const causeOfTransmission: number = this.readBits(8, 1, 2, 6)
                    if (!(0 <= causeOfTransmission && causeOfTransmission <= 63)) {
                        this.recordError(this.instance.causeOfTransmission.getPath(), 'Illegal value')
                    }
                    this.instance.causeOfTransmission.setValue(causeOfTransmission)
                },
                encode: (): void => {
                    const causeOfTransmission: number = this.instance.causeOfTransmission.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.writeBits(8, 1, 2, 6, causeOfTransmission)
                }
            },
            positiveNegativeBit: {
                type: 'integer',
                label: 'Positive/Negative Bit',
                minimum: 0,
                maximum: 1,
                decode: (): void => {
                    const positiveNegativeBit: number = this.readBits(8, 1, 1, 1)
                    if (!(positiveNegativeBit === 1 || positiveNegativeBit === 0)) {
                        this.recordError(this.instance.positiveNegativeBit.getPath(), 'Illegal value')
                    }
                    this.instance.positiveNegativeBit.setValue(positiveNegativeBit)
                },
                encode: (): void => {
                    const positiveNegativeBit: number = this.instance.positiveNegativeBit.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.writeBits(8, 1, 1, 1, positiveNegativeBit)
                }
            },
            testBit: {
                type: 'integer',
                label: 'Test Bit',
                minimum: 0,
                maximum: 1,
                decode: (): void => {
                    const testBit: number = this.readBits(8, 1, 0, 1)
                    if (!(testBit === 1 || testBit === 0)) {
                        this.recordError(this.instance.testBit.getPath(), 'Illegal value')
                    }
                    this.instance.testBit.setValue(testBit)
                },
                encode: (): void => {
                    const testBit: number = this.instance.testBit.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.writeBits(8, 1, 0, 1, testBit)
                }
            },


            originatorAddress: {
                type: 'integer',
                label: 'Originator Address',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    const originatorAddress: number = BufferToUInt8(this.readBytes(9, 1))
                    if (!(0 <= originatorAddress && originatorAddress <= 255)) {
                        this.recordError(this.instance.causeOfTransmission.getPath(), 'Illegal value')
                    }
                    this.instance.originatorAddress.setValue(originatorAddress)
                },
                encode: (): void => {
                    const originatorAddress: number = this.instance.originatorAddress.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.writeBytes(9, UInt8ToBuffer(originatorAddress))
                }
            },
            asduAddressField: {
                type: 'integer',
                label: 'ASDU Address',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    const asduAddressField: number = this.readBytes(10, 2).readUInt16LE()
                    if (!(0 <= asduAddressField && asduAddressField <= 65535)) {
                        this.recordError(this.instance.asduAddressField.getPath(), 'Illegal value')
                    }
                    this.instance.asduAddressField.setValue(asduAddressField)
                },
                encode: (): void => {
                    const asduAddressField: number = this.instance.asduAddressField.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    const buffer: Buffer = UInt16ToBuffer(asduAddressField)
                    const number: number = buffer.readUInt16LE()
                    this.writeBytes(10, UInt16ToBuffer(number))
                }
            },
            IOA: {
                type: 'array',
                label: 'Information Object Address',
                items: {
                    anyOf: [
                        //单点信息 M_SP_NA_1 : SIQ
                        {
                            type: 'object',
                            label: 'Single-point Information Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                SPI: {
                                    type: 'integer',
                                    label: 'Single-point Information',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'SPI', 'BL', 'SB', 'NT', 'IV']
                        },
                        //双点信息 M_DP_NA_1 : DIQ
                        {
                            type: 'object',
                            label: 'Double-point Information Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                DPI: {
                                    type: 'integer',
                                    label: 'Double-point Information',
                                    minimum: 0,
                                    maximum: 3
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'DPI', 'BL', 'SB', 'NT', 'IV']
                        },
                        //步位置信息 M_ST_NA_1 : VTI + QDS
                        {
                            type: 'object',
                            label: 'Step Position Information Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                VTI: {
                                    type: 'integer',
                                    label: 'Value With Transient State Indication',
                                    minimum: -64,
                                    maximum: 63
                                },
                                T: {
                                    type: 'integer',
                                    label: 'Transient State',
                                    minimum: 0,
                                    maximum: 1
                                },
                                OV: {
                                    type: 'integer',
                                    label: 'Overflow Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'VTI', 'T', 'OV', 'BL', 'SB', 'NT', 'IV']
                        },
                        //32比特串 M_BO_NA_1 : BSI + QDS
                        {
                            type: 'object',
                            label: 'Bitstring Of 32 Bits Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                BSI: {
                                    type: 'integer',
                                    label: 'Bitstring Of 32 Bits',
                                    minimum: 0,
                                    maximum: 4294967295
                                },
                                OV: {
                                    type: 'integer',
                                    label: 'Overflow Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'BSI', 'OV', 'BL', 'SB', 'NT', 'IV']
                        },
                        //归一化测量值 M_ME_NA_1 : NVA + QDS
                        {
                            type: 'object',
                            label: 'Measured Value, Normalized Value Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NVA: {
                                    type: 'integer',
                                    label: 'Normalized Value',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                OV: {
                                    type: 'integer',
                                    label: 'Overflow Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'NVA', 'OV', 'BL', 'SB', 'NT', 'IV']
                        },
                        //标量化测量值 M_ME_NB_1 : SVA + QDS
                        {
                            type: 'object',
                            label: 'Measured Value, Normalized Value Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                SVA: {
                                    type: 'integer',
                                    label: 'Scaled Value',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                OV: {
                                    type: 'integer',
                                    label: 'Overflow Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'SVA', 'OV', 'BL', 'SB', 'NT', 'IV']
                        },
                        //浮点型测量值 M_ME_NC_1 : IEEE STD 754 + QDS
                        {
                            type: 'object',
                            label: 'Measured Value, Short Floating Point Value Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                IEEE_STD_754: {
                                    type: 'number',
                                    label: 'Short Floating Point Value'
                                },
                                OV: {
                                    type: 'integer',
                                    label: 'Overflow Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'IEEE_STD_754', 'OV', 'BL', 'SB', 'NT', 'IV']
                        },
                        //累计值 M_IT_NA_1 : BCR
                        {
                            type: 'object',
                            label: 'Integrated Total Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                BCR: {
                                    type: 'number',
                                    label: 'Binary Counter Reading',
                                    minimum: -2147483648,
                                    maximum: 2147483647
                                },
                                SQ: {
                                    type: 'integer',
                                    label: 'Sequence',
                                    minimum: 0,
                                    maximum: 31
                                },
                                CY: {
                                    type: 'integer',
                                    label: 'Carry',
                                    minimum: 0,
                                    maximum: 1
                                },
                                CA: {
                                    type: 'integer',
                                    label: 'Counter Adjusted',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'BCR', 'SQ', 'CY', 'CA', 'IV']
                        },
                        //带状态检出的成组单点信息 M_PS_NA_1 : SCD + QDS
                        {
                            type: 'object',
                            label: 'Packed Single Point Information With Status Change Detection',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                SCD: {
                                    type: 'integer',
                                    label: 'Status And Status Change Detection',
                                    minimum: 0,
                                    maximum: 4294967295
                                },
                                OV: {
                                    type: 'integer',
                                    label: 'Overflow Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'OV', 'BL', 'SB', 'NT', 'IV']
                        },
                        //不带品质描述的归一化测量值 M_ME_ND_1 : NVA
                        {
                            type: 'object',
                            label: 'Measured value, Normalized Value Without Quality Descriptor',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NVA: {
                                    type: 'integer',
                                    label: 'Normalized Value',
                                    minimum: 0,
                                    maximum: 65535
                                }
                            },
                            required: ['address', 'NVA']
                        },
                        //带时标CP56time2a的单点信息 M_SP_TB_1 : SIQ + CP56Time2a
                        {
                            type: 'object',
                            label: 'Single-point Information With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                SPI: {
                                    type: 'integer',
                                    label: 'Single-point Information',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'SPI', 'BL', 'SB', 'NT', 'IV', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的双点信息 M_DP_TB_1 : DIQ + CP56Time2a
                        {
                            type: 'object',
                            label: 'Single-point Information With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                DPI: {
                                    type: 'integer',
                                    label: 'Double-point Information',
                                    minimum: 0,
                                    maximum: 3
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'DPI', 'BL', 'SB', 'NT', 'IV', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的步位置信息 M_ST_TB_1 : VTI + QDS + CP56Time2a
                        {
                            type: 'object',
                            label: 'Single-point Information With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                VTI: {
                                    type: 'integer',
                                    label: 'Value With Transient State Indication',
                                    minimum: -64,
                                    maximum: 63
                                },
                                T: {
                                    type: 'integer',
                                    label: 'Transient State',
                                    minimum: 0,
                                    maximum: 1
                                },
                                OV: {
                                    type: 'integer',
                                    label: 'Overflow Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'VTI', 'T', 'OV', 'BL', 'SB', 'NT', 'IV', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的32比特串 M_BO_TB_1 : BSI + QDS + CP56Time2a
                        {
                            type: 'object',
                            label: 'Single-point Information With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                BSI: {
                                    type: 'integer',
                                    label: 'Bitstring Of 32 Bits',
                                    minimum: 0,
                                    maximum: 4294967295
                                },
                                OV: {
                                    type: 'integer',
                                    label: 'Overflow Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'BSI', 'OV', 'BL', 'SB', 'NT', 'IV', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的归一化测量值 M_ME_TD_1 = NVA + QDS +CP56Time2a
                        {
                            type: 'object',
                            label: 'Single-point Information With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NVA: {
                                    type: 'integer',
                                    label: 'Normalized Value',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                OV: {
                                    type: 'integer',
                                    label: 'Overflow Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'NVA', 'OV', 'BL', 'SB', 'NT', 'IV', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的标量化测量值 M_ME_TE_1 = SVA + QDS +CP56Time2a
                        {
                            type: 'object',
                            label: 'Single-point Information With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                SVA: {
                                    type: 'integer',
                                    label: 'Scaled Value',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                OV: {
                                    type: 'integer',
                                    label: 'Overflow Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'SVA', 'OV', 'BL', 'SB', 'NT', 'IV', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的浮点型测量值 M_ME_TF_1 = IEEE STD 754 + QDS +CP56Time2a
                        {
                            type: 'object',
                            label: 'Single-point Information With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                IEEE_STD_754: {
                                    type: 'number',
                                    label: 'Short Floating Point Value'
                                },
                                OV: {
                                    type: 'integer',
                                    label: 'Overflow Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'IEEE_STD_754', 'OV', 'BL', 'SB', 'NT', 'IV', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的累计值 M_IT_TB_1 = BCR + CP56Time2a
                        {
                            type: 'object',
                            label: 'Single-point Information With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                BCR: {
                                    type: 'number',
                                    label: 'Binary Counter Reading',
                                    minimum: -2147483648,
                                    maximum: 2147483647
                                },
                                SQ: {
                                    type: 'integer',
                                    label: 'Sequence',
                                    minimum: 0,
                                    maximum: 31
                                },
                                CY: {
                                    type: 'integer',
                                    label: 'Carry',
                                    minimum: 0,
                                    maximum: 1
                                },
                                CA: {
                                    type: 'integer',
                                    label: 'Counter Adjusted',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'BCR', 'SQ', 'CY', 'CA', 'IV', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的继电器保护装置事件 M_EP_TD_1 = SEP + CP16Time2a +CP56Time2a
                        {
                            type: 'object',
                            label: 'Event Of Protection Equipment With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                ES: {
                                    type: 'number',
                                    label: 'Event State',
                                    minimum: 0,
                                    maximum: 4
                                },
                                EI: {
                                    type: 'number',
                                    label: 'Elapsed Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds_16: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Milliseconds_56: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'ES', 'EI', 'BL', 'SB', 'NT', 'IV', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的继电器保护装置成组启动事件 M_EP_TE_1 = SEP + QDP + CP16Time2a +CP56Time2a
                        {
                            type: 'object',
                            label: 'Packed Start Events Of Protection Equipment With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                GS: {
                                    type: 'number',
                                    label: 'General Start',
                                    minimum: 0,
                                    maximum: 4
                                },
                                SL1: {
                                    type: 'number',
                                    label: 'Start Of Line 1',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SL2: {
                                    type: 'integer',
                                    label: 'Start Of Line 2',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SL3: {
                                    type: 'integer',
                                    label: 'Start Of Line 3',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SIE: {
                                    type: 'integer',
                                    label: 'Start Of Inverse Event',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SIF: {
                                    type: 'integer',
                                    label: 'Start Of Forward Event',
                                    minimum: 0,
                                    maximum: 1
                                },
                                EI: {
                                    type: 'number',
                                    label: 'Elapsed Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds_16: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Milliseconds_56: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'GS', 'SL1', 'SL2', 'SL3', 'SIE', 'SIF', 'EI', 'BL', 'SB', 'NT', 'IV', 'Milliseconds_16', 'Milliseconds_56', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的继电器保护装置成组输出电路信息 M_EP_TF_1 = OCI + CP16Time2a +CP56Time2a
                        {
                            type: 'object',
                            label: 'Packed Output Circuit Information Of Protection Equipment With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                GC: {
                                    type: 'number',
                                    label: 'General Start',
                                    minimum: 0,
                                    maximum: 4
                                },
                                CL1: {
                                    type: 'number',
                                    label: 'Command To Line 1',
                                    minimum: 0,
                                    maximum: 1
                                },
                                CL2: {
                                    type: 'integer',
                                    label: 'Command To Line 2',
                                    minimum: 0,
                                    maximum: 1
                                },
                                CL3: {
                                    type: 'integer',
                                    label: 'Command To Line 3',
                                    minimum: 0,
                                    maximum: 1
                                },
                                EI: {
                                    type: 'number',
                                    label: 'Elapsed Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                BL: {
                                    type: 'integer',
                                    label: 'Blocked Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                SB: {
                                    type: 'integer',
                                    label: 'Substituted Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                NT: {
                                    type: 'integer',
                                    label: 'Topical Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds_16: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Milliseconds_56: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'GC', 'CL1', 'CL2', 'CL3', 'SIE', 'SIF', 'EI', 'BL', 'SB', 'NT', 'IV', 'Milliseconds_16', 'Milliseconds_56', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //单命令 C_SC_NA_1 = SCO
                        {
                            type: 'object',
                            label: 'Single Command Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                SCS: {
                                    type: 'number',
                                    label: 'Single Command State',
                                    minimum: 0,
                                    maximum: 1
                                },
                                QU: {
                                    type: 'number',
                                    label: 'Qualifier For The Commands',
                                    minimum: 0,
                                    maximum: 31
                                },
                                S_OR_E: {
                                    type: 'integer',
                                    label: 'Select/Execute State',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'SCS', 'QU', 'S_OR_E']
                        },
                        //双命令 C_DC_NA_1 = DCO
                        {
                            type: 'object',
                            label: 'Double Command Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                DCS: {
                                    type: 'number',
                                    label: 'Double Command State',
                                    minimum: 0,
                                    maximum: 4
                                },
                                QU: {
                                    type: 'number',
                                    label: 'Qualifier For The Commands',
                                    minimum: 0,
                                    maximum: 31
                                },
                                S_OR_E: {
                                    type: 'integer',
                                    label: 'Select/Execute State',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'SCS', 'QU', 'S_OR_E']
                        },
                        //步调节命令 C_RC_NA_1 = RCO
                        {
                            type: 'object',
                            label: 'Regulating Step Command Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                RCS: {
                                    type: 'number',
                                    label: 'Status Information Of The Step Command',
                                    minimum: 0,
                                    maximum: 4
                                },
                                QU: {
                                    type: 'number',
                                    label: 'Qualifier For The Commands',
                                    minimum: 0,
                                    maximum: 31
                                },
                                S_OR_E: {
                                    type: 'integer',
                                    label: 'Select/Execute State',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'RCS', 'QU', 'S_OR_E']
                        },
                        //设点命令，归一化值 C_SE_NA_1 = NVA + QOS
                        {
                            type: 'object',
                            label: 'Set-point Command, Normalized Value Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NVA: {
                                    type: 'integer',
                                    label: 'Normalized Value',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                QL: {
                                    type: 'number',
                                    label: 'Qualifier Of Set-point Command',
                                    minimum: 0,
                                    maximum: 63
                                },
                                S_OR_E: {
                                    type: 'integer',
                                    label: 'Select/Execute State',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'NVA', 'QL', 'S_OR_E']
                        },
                        // //设点命令，标量值 C_SE_NB_1 = SVA + QOS
                        {
                            type: 'object',
                            label: 'Set-point Command, Scaled Value Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                SVA: {
                                    type: 'integer',
                                    label: 'Scaled Value',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                QL: {
                                    type: 'number',
                                    label: 'Qualifier Of Set-point Command',
                                    minimum: 0,
                                    maximum: 63
                                },
                                S_OR_E: {
                                    type: 'integer',
                                    label: 'Select/Execute State',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'SVA', 'QL', 'S_OR_E']
                        },
                        //设点命令，短浮点值 C_SE_NC_1 = IEEE STD 754 + QOS
                        {
                            type: 'object',
                            label: 'Set-point Command, Short Floating Point Value Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                IEEE_STD_754: {
                                    type: 'number',
                                    label: 'Short Floating Point Value'
                                },
                                QL: {
                                    type: 'integer',
                                    label: 'Qualifier Of Set-point Command',
                                    minimum: 0,
                                    maximum: 63
                                },
                                S_OR_E: {
                                    type: 'integer',
                                    label: 'Select/Execute State',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'IEEE_STD_754', 'QL', 'S_OR_E']
                        },
                        //32比特串 C_BO_NA_1 = BSI
                        {
                            type: 'object',
                            label: 'Bitstring Of 32 Bits Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                BSI: {
                                    type: 'integer',
                                    label: 'Bitstring Of 32 Bits',
                                    minimum: 0,
                                    maximum: 4294967295
                                }
                            },
                            required: ['address', 'BSI']
                        },
                        //带时标CP56time2a的单命令 C_SC_TA_1 = SCO + CP56Time2a
                        {
                            type: 'object',
                            label: 'Single Command With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                SCS: {
                                    type: 'number',
                                    label: 'Single Command State',
                                    minimum: 0,
                                    maximum: 1
                                },
                                QU: {
                                    type: 'number',
                                    label: 'Qualifier For The Commands',
                                    minimum: 0,
                                    maximum: 31
                                },
                                S_OR_E: {
                                    type: 'integer',
                                    label: 'Select/Execute State',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'SCS', 'QU', 'S_OR_E', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的双命令 C_DC_TA_1 = DCO + CP56Time2a
                        {
                            type: 'object',
                            label: 'Double Command With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                DCS: {
                                    type: 'number',
                                    label: 'Double Command State',
                                    minimum: 0,
                                    maximum: 4
                                },
                                QU: {
                                    type: 'number',
                                    label: 'Qualifier For The Commands',
                                    minimum: 0,
                                    maximum: 31
                                },
                                S_OR_E: {
                                    type: 'integer',
                                    label: 'Select/Execute State',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'DCS', 'QU', 'S_OR_E', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的步调节命令 C_RC_TA_1 = RCO + CP56Time2a
                        {
                            type: 'object',
                            label: 'Regulating Step Command With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                RCS: {
                                    type: 'number',
                                    label: 'Status Information Of The Step Command',
                                    minimum: 0,
                                    maximum: 4
                                },
                                QU: {
                                    type: 'number',
                                    label: 'Qualifier For The Commands',
                                    minimum: 0,
                                    maximum: 31
                                },
                                S_OR_E: {
                                    type: 'integer',
                                    label: 'Select/Execute State',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'RCS', 'QU', 'S_OR_E', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的设点命令，归一化值 C_SE_TA_1 = NVA + QOS + CP56Time2a
                        {
                            type: 'object',
                            label: 'Set-point Command, Normalized Value With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NVA: {
                                    type: 'integer',
                                    label: 'Normalized Value',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                QL: {
                                    type: 'number',
                                    label: 'Qualifier Of Set-point Command',
                                    minimum: 0,
                                    maximum: 63
                                },
                                S_OR_E: {
                                    type: 'integer',
                                    label: 'Select/Execute State',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'NVA', 'QL', 'S_OR_E', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的设点命令，标量值 C_SE_TB_1 = SVA + QOS + CP56Time2a
                        {
                            type: 'object',
                            label: 'Set-point Command, Scaled Value With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                SVA: {
                                    type: 'integer',
                                    label: 'Scaled Value',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                QL: {
                                    type: 'number',
                                    label: 'Qualifier Of Set-point Command',
                                    minimum: 0,
                                    maximum: 63
                                },
                                S_OR_E: {
                                    type: 'integer',
                                    label: 'Select/Execute State',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'SVA', 'QL', 'S_OR_E', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的设点命令，短浮点值 C_SE_TC_1 = IEEE STD 754 + QOS + CP56Time2a
                        {
                            type: 'object',
                            label: 'Set-point Command, Short Floating Point Value With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                IEEE_STD_754: {
                                    type: 'number',
                                    label: 'Short Floating Point Value'
                                },
                                QL: {
                                    type: 'number',
                                    label: 'Qualifier Of Set-point Command',
                                    minimum: 0,
                                    maximum: 63
                                },
                                S_OR_E: {
                                    type: 'integer',
                                    label: 'Select/Execute State',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'IEEE_STD_754', 'QL', 'S_OR_E', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //带时标CP56time2a的32比特串 C_BO_TA_1 = BSI + CP56Time2a
                        {
                            type: 'object',
                            label: 'Bitstring Of 32 Bits With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                BSI: {
                                    type: 'integer',
                                    label: 'Bitstring Of 32 Bits',
                                    minimum: 0,
                                    maximum: 4294967295
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'BSI', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //初始化结束 M_EI_NA_1 = COI
                        {
                            type: 'object',
                            label: 'End Of Initialization',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                COI: {
                                    type: 'integer',
                                    label: 'Cause Of Initialization',
                                    minimum: 0,
                                    maximum: 127
                                },
                                LPC: {
                                    type: 'integer',
                                    label: 'Local Parameter Change Flag',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'BSI', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //总召唤命令 C_IC_NA_1 = QOI
                        {
                            type: 'object',
                            label: 'Interrogation Command',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                QOI: {
                                    type: 'integer',
                                    label: 'Qualifier Of Interrogation Command',
                                    minimum: 0,
                                    maximum: 255
                                }
                            },
                            required: ['address', 'QOI']
                        },
                        //电能脉冲召唤命令 C_CI_NA_1 = QCC
                        {
                            type: 'object',
                            label: 'Counter Interrogation Command',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                RQI: {
                                    type: 'integer',
                                    label: 'Request Qualifier Of Counter Interrogation Command',
                                    minimum: 0,
                                    maximum: 63
                                },
                                FRZ: {
                                    type: 'integer',
                                    label: 'Freeze/reset Qualifier Of Counter Interrogation Command',
                                    minimum: 0,
                                    maximum: 3
                                }
                            },
                            required: ['address', 'RQI', 'FRZ']
                        },
                        //读命令 C_RD_NA_1 = NULL
                        {
                            type: 'object',
                            label: 'Read Command',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                READ: {
                                    type: 'integer',
                                    label: 'Read',
                                    minimum: 0,
                                    maximum: 255
                                }
                            },
                            required: ['address', 'READ']
                        },
                        //时钟同步命令 C_CS_NA_1 = CP56Time2a
                        {
                            type: 'object',
                            label: 'CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //(IEC101)Test Command C_TS_NA_1 = FBP
                        {
                            type: 'object',
                            label: 'Test Command Without Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                FBP: {
                                    type: 'integer',
                                    label: 'Fixed Test Pattern',
                                    minimum: 0,
                                    maximum: 65535
                                }
                            },
                            required: ['address', 'FBP']
                        },
                        //复位进程命令 C_RP_NA_1 = QRP
                        {
                            type: 'object',
                            label: 'Reset Process Command',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                QRP: {
                                    type: 'integer',
                                    label: 'Qualifier for the process reset command',
                                    minimum: 0,
                                    maximum: 255
                                }
                            },
                            required: ['address', 'QRP']
                        },
                        //带时标CP56time2a的测试命令 C_TS_TA_1 = TSC + CP56time2a
                        {
                            type: 'object',
                            label: 'Test Command With CP56Time2a Time Tag',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                TSC: {
                                    type: 'integer',
                                    label: 'Test Counter',
                                    minimum: 0,
                                    maximum: 255
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'TSC', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //归一化测量值 P_ME_NA_1 = NVA + QPM
                        {
                            type: 'object',
                            label: 'Parameter Of Measured Value, Normalized Value',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NVA: {
                                    type: 'integer',
                                    label: 'Normalized Value',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                KPA: {
                                    type: 'integer',
                                    label: 'Kind Of Parameter',
                                    minimum: 0,
                                    maximum: 63
                                },
                                POP: {
                                    type: 'integer',
                                    label: 'POP',
                                    minimum: 0,
                                    maximum: 1
                                },
                                LPC: {
                                    type: 'integer',
                                    label: 'Local Parameter Change Flag',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'NVA', 'KPA', 'POP', 'LPC']
                        },
                        //标量化测量值 P_ME_NB_1 = SVA + QPM
                        {
                            type: 'object',
                            label: 'Parameter Of Measured Value, Scaled Value',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                SVA: {
                                    type: 'integer',
                                    label: 'Scaled Value',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                KPA: {
                                    type: 'integer',
                                    label: 'Kind Of Parameter',
                                    minimum: 0,
                                    maximum: 63
                                },
                                POP: {
                                    type: 'integer',
                                    label: 'POP',
                                    minimum: 0,
                                    maximum: 1
                                },
                                LPC: {
                                    type: 'integer',
                                    label: 'Local Parameter Change Flag',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'SVA', 'KPA', 'POP', 'LPC']
                        },
                        //浮点测量值 P_ME_NC_1 = IEEE STD 754 + QPM
                        {
                            type: 'object',
                            label: 'Parameter Of Measured Value, Short Floating Point Value',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                IEEE_STD_754: {
                                    type: 'number',
                                    label: 'Short Floating Point Value'
                                },
                                KPA: {
                                    type: 'integer',
                                    label: 'Kind Of Parameter',
                                    minimum: 0,
                                    maximum: 63
                                },
                                POP: {
                                    type: 'integer',
                                    label: 'POP',
                                    minimum: 0,
                                    maximum: 1
                                },
                                LPC: {
                                    type: 'integer',
                                    label: 'Local Parameter Change Flag',
                                    minimum: 0,
                                    maximum: 1
                                }
                            },
                            required: ['address', 'IEEE_STD_754', 'KPA', 'POP', 'LPC']
                        },
                        //参数激活 P_AC_NA_1 = QPA
                        {
                            type: 'object',
                            label: 'Parameter Activation',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                QPA: {
                                    type: 'integer',
                                    label: 'Qualifier Of The Parameter Activation',
                                    minimum: 0,
                                    maximum: 255
                                }
                            },
                            required: ['address', 'QPA']
                        },
                        //文件已准备好 F_FR_NA_1 = NOF + LOF + FRQ
                        {
                            type: 'object',
                            label: 'File Ready',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NOF: {
                                    type: 'integer',
                                    label: 'Name Of File',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                LOF: {
                                    type: 'integer',
                                    label: 'Length Of File',
                                    minimum: 0,
                                    maximum: 255
                                },
                                FRQ: {
                                    type: 'integer',
                                    label: 'File Ready Qualifier',
                                    minimum: 0,
                                    maximum: 255
                                }
                            },
                            required: ['address', 'NOF', 'LOF', 'FRQ']
                        },
                        //节点已准备好 F_SR_NA_1 = NOF + NOS + LOF + SRQ
                        {
                            type: 'object',
                            label: 'Section ready',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NOF: {
                                    type: 'integer',
                                    label: 'Name Of File',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                NOS: {
                                    type: 'integer',
                                    label: 'Name Of Segment',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                LOF: {
                                    type: 'integer',
                                    label: 'Length Of File',
                                    minimum: 0,
                                    maximum: 255
                                },
                                SRQ: {
                                    type: 'integer',
                                    label: 'Section Ready Qualifier',
                                    minimum: 0,
                                    maximum: 255
                                }
                            },
                            required: ['address', 'NOF', 'NOS', 'LOF', 'SRQ']
                        },
                        //召唤目录，选择文件，召唤文件，选择节 F_SC_NA_1 = NOF + NOS + SCQ
                        {
                            type: 'object',
                            label: 'Call Directory, Select File, Call File, Call Section',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NOF: {
                                    type: 'integer',
                                    label: 'Name Of File',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                NOS: {
                                    type: 'integer',
                                    label: 'Name Of Segment',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                SCQ: {
                                    type: 'integer',
                                    label: 'Selection And Call Qualifier',
                                    minimum: 0,
                                    maximum: 255
                                }
                            },
                            required: ['address', 'NOF', 'NOS', 'SCQ']
                        },
                        //最后的节，最后的段 F_LS_NA_1 = NOF + NOS + LSQ + CHS
                        {
                            type: 'object',
                            label: 'Last Section, Last Segment',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NOF: {
                                    type: 'integer',
                                    label: 'Name Of File',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                NOS: {
                                    type: 'integer',
                                    label: 'Name Of Segment',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                LSQ: {
                                    type: 'integer',
                                    label: 'Last Segment Qualifier',
                                    minimum: 0,
                                    maximum: 255
                                },
                                CHS: {
                                    type: 'integer',
                                    label: 'Checksum',
                                    minimum: 0,
                                    maximum: 255
                                }
                            },
                            required: ['address', 'NOF', 'NOS', 'LSQ', 'CHS']
                        },
                        //确认文件，确认节 F_FA_NA_1 = NOF + NOS + AFQ
                        {
                            type: 'object',
                            label: 'ACK File, ACK Section',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NOF: {
                                    type: 'integer',
                                    label: 'Name Of File',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                NOS: {
                                    type: 'integer',
                                    label: 'Name Of Segment',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                AFQ: {
                                    type: 'integer',
                                    label: 'Confirmation Qualifier',
                                    minimum: 0,
                                    maximum: 255
                                }
                            },
                            required: ['address', 'NOF', 'NOS', 'AFQ']
                        },
                        //段 F_SG_NA_1 = NOF + NOS + LOS + Segment
                        {
                            type: 'object',
                            label: 'Segment',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NOF: {
                                    type: 'integer',
                                    label: 'Name Of File',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                NOS: {
                                    type: 'integer',
                                    label: 'Name Of Segment',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                LOS: {
                                    type: 'integer',
                                    label: 'Length Of Segment',
                                    minimum: 0,
                                    maximum: 255
                                },
                                Segment: {
                                    type: 'string',
                                    label: 'Segment'
                                }
                            },
                            required: ['address', 'NOF', 'NOS', 'LOS', 'Segment']
                        },
                        //目录 F_DR_TA_1 = NOF + LOF + SOF + CP56Time2a
                        {
                            type: 'object',
                            label: 'Directory',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NOF: {
                                    type: 'integer',
                                    label: 'Name Of File',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                LOF: {
                                    type: 'integer',
                                    label: 'Length Of File',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                LOS: {
                                    type: 'integer',
                                    label: 'Length Of Segment',
                                    minimum: 0,
                                    maximum: 255
                                },
                                Milliseconds: {
                                    type: 'integer',
                                    label: 'Milliseconds',
                                    minimum: 0,
                                    maximum: 59999
                                },
                                Minutes: {
                                    type: 'integer',
                                    label: 'Minute',
                                    minimum: 0,
                                    maximum: 59
                                },
                                GEN: {
                                    type: 'integer',
                                    label: 'Reserved',
                                    minimum: 0,
                                    maximum: 1
                                },
                                MIN_IV: {
                                    type: 'integer',
                                    label: 'Invalid Quality Flag',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Hours: {
                                    type: 'integer',
                                    label: 'Hour ',
                                    minimum: 0,
                                    maximum: 23
                                },
                                SU: {
                                    type: 'integer',
                                    label: 'Summer Time',
                                    minimum: 0,
                                    maximum: 1
                                },
                                Day: {
                                    type: 'integer',
                                    label: 'Day Of The Month',
                                    minimum: 1,
                                    maximum: 31
                                },
                                DOW: {
                                    type: 'integer',
                                    label: 'Day Of The Week',
                                    minimum: 0,
                                    maximum: 7
                                },
                                Month: {
                                    type: 'integer',
                                    label: 'Month',
                                    minimum: 1,
                                    maximum: 12
                                },
                                Year: {
                                    type: 'integer',
                                    label: 'Year',
                                    minimum: 0,
                                    maximum: 99
                                }
                            },
                            required: ['address', 'NOF', 'LOF', 'LOS', 'Milliseconds', 'Minutes', 'GEN', 'MIN_IV', 'Hours', 'SU', 'Day', 'DOW', 'Month', 'Year']
                        },
                        //日志查询，请求存档文件 F_SC_NB_1 = NOF + SCQ
                        {
                            type: 'object',
                            label: 'File Call Confirmation',
                            properties: {
                                address: {
                                    type: 'integer',
                                    label: 'Address',
                                    minimum: 0,
                                    maximum: 16777215
                                },
                                NOF: {
                                    type: 'integer',
                                    label: 'Name Of File',
                                    minimum: 0,
                                    maximum: 65535
                                },
                                SCQ: {
                                    type: 'integer',
                                    label: 'Select And Call Qualifier',
                                    minimum: 0,
                                    maximum: 255
                                }
                            },
                            required: ['address', 'NOF', 'SCQ']
                        }

                    ]
                },

                decode: (): void => {
                    const numberOfObject: number = this.instance.numberOfObject.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    const typeId: number = this.instance.messageTypeId.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    const apduLength: number = this.instance.apduLength.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    const ioaTotalLength: number = apduLength - 10
                    const ioaLength: number = ioaTotalLength / numberOfObject
                    const IOA_arr: any[] = []
                    Loop: for (let i = 1; i <= numberOfObject; i++) {
                        const address: number = this.readBytes(12 + (i - 1) * ioaLength, 3).readUInt16LE()
                        const buffer: Buffer = Buffer.alloc(3)
                        buffer.writeUintBE(address, 0, 3)
                        if (!(0 <= address && address <= 16777215)) {
                            this.recordError(this.instance.IOA_address.getPath(), 'Illegal value')
                        }
                        switch (typeId) {
                            //单点信息 M_SP_NA_1 : SIQ
                            case 1: {
                                const SPI: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const M_SP_NA_1: {
                                    address: number,
                                    SPI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                } = {
                                    address: 0,
                                    SPI: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0
                                }
                                M_SP_NA_1.address = buffer.readUintBE(0, 3)
                                M_SP_NA_1.SPI = SPI
                                M_SP_NA_1.BL = BL
                                M_SP_NA_1.SB = SB
                                M_SP_NA_1.NT = NT
                                M_SP_NA_1.IV = IV
                                IOA_arr.push(M_SP_NA_1)
                            }
                                break
                            //双点信息 M_DP_NA_1 : DIQ
                            case 3: {
                                const DPI: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 4, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 1, 1)
                                const M_DP_NA_1: {
                                    address: number,
                                    DPI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                } = {
                                    address: 0,
                                    DPI: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0
                                }
                                M_DP_NA_1.address = buffer.readUintBE(0, 3)
                                M_DP_NA_1.DPI = DPI
                                M_DP_NA_1.BL = BL
                                M_DP_NA_1.SB = SB
                                M_DP_NA_1.NT = NT
                                M_DP_NA_1.IV = IV
                                IOA_arr.push(M_DP_NA_1)
                            }
                                break
                            //步位置信息 M_ST_NA_1 : VTI + QDS
                            case 5: {
                                const VTI: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 1, 7)
                                const T: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const OV: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 0, 1)
                                const M_ST_NA_1: {
                                    address: number,
                                    VTI: number,
                                    T: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                } = {
                                    address: 0,
                                    VTI: 0,
                                    T: 0,
                                    OV: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0
                                }
                                M_ST_NA_1.address = buffer.readUintBE(0, 3)
                                M_ST_NA_1.VTI = VTI
                                M_ST_NA_1.T = T
                                M_ST_NA_1.OV = OV
                                M_ST_NA_1.BL = BL
                                M_ST_NA_1.SB = SB
                                M_ST_NA_1.NT = NT
                                M_ST_NA_1.IV = IV
                                IOA_arr.push(M_ST_NA_1)
                            }
                                break
                            //32比特串 M_BO_NA_1 : BSI + QDS
                            case 7: {
                                const BSI: number = BufferToUInt32(this.readBytes(12 + (i - 1) * ioaLength + 3, 4))
                                const OV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const M_BO_NA_1: {
                                    address: number,
                                    BSI: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                } = {
                                    address: 0,
                                    BSI: 0,
                                    OV: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0
                                }
                                M_BO_NA_1.address = buffer.readUintBE(0, 3)
                                M_BO_NA_1.BSI = BSI
                                M_BO_NA_1.OV = OV
                                M_BO_NA_1.BL = BL
                                M_BO_NA_1.SB = SB
                                M_BO_NA_1.NT = NT
                                M_BO_NA_1.IV = IV
                                IOA_arr.push(M_BO_NA_1)
                            }
                                break
                            //归一化测量值 M_ME_NA_1 : NVA + QDS
                            case 9: {
                                const NVA: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUInt16LE()
                                const OV: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1)
                                const M_ME_NA_1: {
                                    address: number,
                                    NVA: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                } = {
                                    address: 0,
                                    NVA: 0,
                                    OV: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0
                                }
                                M_ME_NA_1.address = buffer.readUintBE(0, 3)
                                M_ME_NA_1.NVA = NVA
                                M_ME_NA_1.OV = OV
                                M_ME_NA_1.BL = BL
                                M_ME_NA_1.SB = SB
                                M_ME_NA_1.NT = NT
                                M_ME_NA_1.IV = IV
                                IOA_arr.push(M_ME_NA_1)
                            }
                                break
                            //标量化测量值 M_ME_NB_1 : SVA + QDS
                            case 11: {
                                const SVA: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUInt16LE()
                                const OV: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1)
                                const M_ME_NB_1: {
                                    address: number,
                                    SVA: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                } = {
                                    address: 0,
                                    SVA: 0,
                                    OV: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0
                                }
                                M_ME_NB_1.address = buffer.readUintBE(0, 3)
                                M_ME_NB_1.SVA = SVA
                                M_ME_NB_1.OV = OV
                                M_ME_NB_1.BL = BL
                                M_ME_NB_1.SB = SB
                                M_ME_NB_1.NT = NT
                                M_ME_NB_1.IV = IV
                                IOA_arr.push(M_ME_NB_1)
                            }
                                break
                            //浮点型测量值 M_ME_NC_1 : IEEE STD 754 + QDS
                            case 13: {
                                const IEEE_STD_754: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 4).readFloatLE()
                                const OV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const M_ME_NC_1: {
                                    address: number,
                                    IEEE_STD_754: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                } = {
                                    address: 0,
                                    IEEE_STD_754: 0,
                                    OV: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0
                                }
                                M_ME_NC_1.address = buffer.readUintBE(0, 3)
                                M_ME_NC_1.IEEE_STD_754 = IEEE_STD_754
                                M_ME_NC_1.OV = OV
                                M_ME_NC_1.BL = BL
                                M_ME_NC_1.SB = SB
                                M_ME_NC_1.NT = NT
                                M_ME_NC_1.IV = IV
                                IOA_arr.push(M_ME_NC_1)
                            }
                                break
                            //累计值 M_IT_NA_1 : BCR
                            case 15: {
                                const BCR: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 4).readInt32LE()
                                const SQ: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const CA: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1)
                                const CY: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1)
                                const M_IT_NA_1: {
                                    address: number,
                                    BCR: number,
                                    SQ: number,
                                    CY: number,
                                    CA: number,
                                    IV: number,
                                } = {
                                    address: 0,
                                    BCR: 0,
                                    SQ: 0,
                                    CY: 0,
                                    CA: 0,
                                    IV: 0
                                }
                                M_IT_NA_1.address = buffer.readUintBE(0, 3)
                                M_IT_NA_1.BCR = BCR
                                M_IT_NA_1.SQ = SQ
                                M_IT_NA_1.CY = CY
                                M_IT_NA_1.CA = CA
                                M_IT_NA_1.IV = IV
                                IOA_arr.push(M_IT_NA_1)
                            }
                                break
                            //带状态检出的成组单点信息 M_PS_NA_1 : SCD + QDS
                            case 20: {
                                const SCD: number = BufferToUInt32(this.readBytes(12 + (i - 1) * ioaLength + 3, 4))
                                const OV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const M_PS_NA_1: {
                                    address: number,
                                    SCD: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                } = {
                                    address: 0,
                                    SCD: 0,
                                    OV: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0
                                }
                                M_PS_NA_1.address = buffer.readUintBE(0, 3)
                                M_PS_NA_1.SCD = SCD
                                M_PS_NA_1.OV = OV
                                M_PS_NA_1.BL = BL
                                M_PS_NA_1.SB = SB
                                M_PS_NA_1.NT = NT
                                M_PS_NA_1.IV = IV
                                IOA_arr.push(M_PS_NA_1)
                            }
                                break
                            //不带品质描述的归一化测量值 M_ME_ND_1 : NVA
                            case 21: {
                                const NVA: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUInt16LE()
                                const M_ME_ND_1: {
                                    address: number,
                                    NVA: number,
                                } = {
                                    address: 0,
                                    NVA: 0
                                }
                                M_ME_ND_1.address = buffer.readUintBE(0, 3)
                                M_ME_ND_1.NVA = NVA
                                IOA_arr.push(M_ME_ND_1)
                            }
                                break
                            //带时标CP56time2a的单点信息 M_SP_TB_1 : SIQ + CP56Time2a
                            case 30: {
                                const SPI: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 4, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 1, 7)
                                const M_SP_TB_1: {
                                    address: number,
                                    SPI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    SPI: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                M_SP_TB_1.address = buffer.readUintBE(0, 3)
                                M_SP_TB_1.SPI = SPI
                                M_SP_TB_1.BL = BL
                                M_SP_TB_1.SB = SB
                                M_SP_TB_1.NT = NT
                                M_SP_TB_1.IV = IV
                                M_SP_TB_1.Milliseconds = Milliseconds
                                M_SP_TB_1.Minutes = Minutes
                                M_SP_TB_1.GEN = GEN
                                M_SP_TB_1.MIN_IV = MIN_IV
                                M_SP_TB_1.Hours = Hours
                                M_SP_TB_1.SU = SU
                                M_SP_TB_1.Day = Day
                                M_SP_TB_1.DOW = DOW
                                M_SP_TB_1.Month = Month
                                M_SP_TB_1.Year = Year
                                IOA_arr.push(M_SP_TB_1)
                            }
                                break
                            //带时标CP56time2a的双点信息 M_DP_TB_1 : DIQ + CP56Time2a
                            case 31: {
                                const DPI: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 4, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 1, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 4, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 1, 7)
                                const M_DP_TB_1: {
                                    address: number,
                                    DPI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    DPI: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                M_DP_TB_1.address = buffer.readUintBE(0, 3)
                                M_DP_TB_1.DPI = DPI
                                M_DP_TB_1.BL = BL
                                M_DP_TB_1.SB = SB
                                M_DP_TB_1.NT = NT
                                M_DP_TB_1.IV = IV
                                M_DP_TB_1.Milliseconds = Milliseconds
                                M_DP_TB_1.Minutes = Minutes
                                M_DP_TB_1.GEN = GEN
                                M_DP_TB_1.MIN_IV = MIN_IV
                                M_DP_TB_1.Hours = Hours
                                M_DP_TB_1.SU = SU
                                M_DP_TB_1.Day = Day
                                M_DP_TB_1.DOW = DOW
                                M_DP_TB_1.Month = Month
                                M_DP_TB_1.Year = Year
                                IOA_arr.push(M_DP_TB_1)
                            }
                                break
                            //带时标CP56time2a的步位置信息 M_ST_TB_1 : VTI + QDS + CP56Time2a
                            case 32: {
                                const VTI: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 1, 7)
                                const T: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const OV: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 0, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 5, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 1, 7)
                                const M_ST_TB_1: {
                                    address: number,
                                    VTI: number,
                                    T: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    VTI: 0,
                                    T: 0,
                                    OV: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                M_ST_TB_1.address = buffer.readUintBE(0, 3)
                                M_ST_TB_1.VTI = VTI
                                M_ST_TB_1.T = T
                                M_ST_TB_1.OV = OV
                                M_ST_TB_1.BL = BL
                                M_ST_TB_1.SB = SB
                                M_ST_TB_1.NT = NT
                                M_ST_TB_1.IV = IV
                                M_ST_TB_1.Milliseconds = Milliseconds
                                M_ST_TB_1.Minutes = Minutes
                                M_ST_TB_1.GEN = GEN
                                M_ST_TB_1.MIN_IV = MIN_IV
                                M_ST_TB_1.Hours = Hours
                                M_ST_TB_1.SU = SU
                                M_ST_TB_1.Day = Day
                                M_ST_TB_1.DOW = DOW
                                M_ST_TB_1.Month = Month
                                M_ST_TB_1.Year = Year
                                IOA_arr.push(M_ST_TB_1)
                            }
                                break
                            //带时标CP56time2a的32比特串 M_BO_TB_1 : BSI + QDS + CP56Time2a
                            case 33: {
                                const BSI: number = BufferToUInt32(this.readBytes(12 + (i - 1) * ioaLength + 3, 4))
                                const OV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 8, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 13, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 14, 1, 1, 7)
                                const M_BO_TB_1: {
                                    address: number,
                                    BSI: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    BSI: 0,
                                    OV: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                M_BO_TB_1.address = buffer.readUintBE(0, 3)
                                M_BO_TB_1.BSI = BSI
                                M_BO_TB_1.OV = OV
                                M_BO_TB_1.BL = BL
                                M_BO_TB_1.SB = SB
                                M_BO_TB_1.NT = NT
                                M_BO_TB_1.IV = IV
                                M_BO_TB_1.Milliseconds = Milliseconds
                                M_BO_TB_1.Minutes = Minutes
                                M_BO_TB_1.GEN = GEN
                                M_BO_TB_1.MIN_IV = MIN_IV
                                M_BO_TB_1.Hours = Hours
                                M_BO_TB_1.SU = SU
                                M_BO_TB_1.Day = Day
                                M_BO_TB_1.DOW = DOW
                                M_BO_TB_1.Month = Month
                                M_BO_TB_1.Year = Year
                                IOA_arr.push(M_BO_TB_1)
                            }
                                break
                            //带时标CP56time2a的归一化测量值 M_ME_TD_1 = NVA + QDS +CP56Time2a
                            case 34: {
                                const NVA: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUInt16LE()
                                const OV: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 6, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 1, 7)
                                const M_ME_TD_1: {
                                    address: number,
                                    NVA: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    NVA: 0,
                                    OV: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                M_ME_TD_1.address = buffer.readUintBE(0, 3)
                                M_ME_TD_1.NVA = NVA
                                M_ME_TD_1.OV = OV
                                M_ME_TD_1.BL = BL
                                M_ME_TD_1.SB = SB
                                M_ME_TD_1.NT = NT
                                M_ME_TD_1.IV = IV
                                M_ME_TD_1.Milliseconds = Milliseconds
                                M_ME_TD_1.Minutes = Minutes
                                M_ME_TD_1.GEN = GEN
                                M_ME_TD_1.MIN_IV = MIN_IV
                                M_ME_TD_1.Hours = Hours
                                M_ME_TD_1.SU = SU
                                M_ME_TD_1.Day = Day
                                M_ME_TD_1.DOW = DOW
                                M_ME_TD_1.Month = Month
                                M_ME_TD_1.Year = Year
                                IOA_arr.push(M_ME_TD_1)
                            }
                                break
                            //带时标CP56time2a的标量化测量值 M_ME_TE_1 = SVA + QDS +CP56Time2a
                            case 35: {
                                const SVA: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUInt16LE()
                                const OV: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 6, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 1, 7)
                                const M_ME_TE_1: {
                                    address: number,
                                    SVA: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    SVA: 0,
                                    OV: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                M_ME_TE_1.address = buffer.readUintBE(0, 3)
                                M_ME_TE_1.SVA = SVA
                                M_ME_TE_1.OV = OV
                                M_ME_TE_1.BL = BL
                                M_ME_TE_1.SB = SB
                                M_ME_TE_1.NT = NT
                                M_ME_TE_1.IV = IV
                                M_ME_TE_1.Milliseconds = Milliseconds
                                M_ME_TE_1.Minutes = Minutes
                                M_ME_TE_1.GEN = GEN
                                M_ME_TE_1.MIN_IV = MIN_IV
                                M_ME_TE_1.Hours = Hours
                                M_ME_TE_1.SU = SU
                                M_ME_TE_1.Day = Day
                                M_ME_TE_1.DOW = DOW
                                M_ME_TE_1.Month = Month
                                M_ME_TE_1.Year = Year
                                IOA_arr.push(M_ME_TE_1)
                            }
                                break
                            //带时标CP56time2a的浮点型测量值 M_ME_TF_1 = IEEE STD 754 + QDS +CP56Time2a
                            case 36: {
                                const IEEE_STD_754: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 4).readFloatLE()
                                const OV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 7, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 8, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 13, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 14, 1, 1, 7)
                                const M_ME_TF_1: {
                                    address: number,
                                    IEEE_STD_754: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    IEEE_STD_754: 0,
                                    OV: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                M_ME_TF_1.address = buffer.readUintBE(0, 3)
                                M_ME_TF_1.IEEE_STD_754 = IEEE_STD_754
                                M_ME_TF_1.OV = OV
                                M_ME_TF_1.BL = BL
                                M_ME_TF_1.SB = SB
                                M_ME_TF_1.NT = NT
                                M_ME_TF_1.IV = IV
                                M_ME_TF_1.Milliseconds = Milliseconds
                                M_ME_TF_1.Minutes = Minutes
                                M_ME_TF_1.GEN = GEN
                                M_ME_TF_1.MIN_IV = MIN_IV
                                M_ME_TF_1.Hours = Hours
                                M_ME_TF_1.SU = SU
                                M_ME_TF_1.Day = Day
                                M_ME_TF_1.DOW = DOW
                                M_ME_TF_1.Month = Month
                                M_ME_TF_1.Year = Year
                                IOA_arr.push(M_ME_TF_1)
                            }
                                break
                            //带时标CP56time2a的累计值 M_IT_TB_1 = BCR + CP56Time2a
                            case 37: {
                                const BCR: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 4).readInt32LE()
                                const SQ: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const CA: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1)
                                const CY: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 8, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 13, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 14, 1, 1, 7)
                                const M_IT_TB_1: {
                                    address: number,
                                    BCR: number,
                                    SQ: number,
                                    IV: number,
                                    CA: number,
                                    CY: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    BCR: 0,
                                    SQ: 0,
                                    IV: 0,
                                    CA: 0,
                                    CY: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                M_IT_TB_1.address = buffer.readUintBE(0, 3)
                                M_IT_TB_1.BCR = BCR
                                M_IT_TB_1.SQ = SQ
                                M_IT_TB_1.IV = IV
                                M_IT_TB_1.CA = CA
                                M_IT_TB_1.CY = CY
                                M_IT_TB_1.Milliseconds = Milliseconds
                                M_IT_TB_1.Minutes = Minutes
                                M_IT_TB_1.GEN = GEN
                                M_IT_TB_1.MIN_IV = MIN_IV
                                M_IT_TB_1.Hours = Hours
                                M_IT_TB_1.SU = SU
                                M_IT_TB_1.Day = Day
                                M_IT_TB_1.DOW = DOW
                                M_IT_TB_1.Month = Month
                                M_IT_TB_1.Year = Year
                                IOA_arr.push(M_IT_TB_1)
                            }
                                break
                            //带时标CP56time2a的继电器保护装置事件 M_EP_TD_1 = SEP + CP16Time2a +CP56Time2a
                            case 38: {
                                const ES: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2)
                                const EI: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 4, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const Milliseconds_16: number = this.readBytes(12 + (i - 1) * ioaLength + 4, 2).readUInt16LE()
                                const Milliseconds_56: number = this.readBytes(12 + (i - 1) * ioaLength + 6, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 1, 7)
                                const M_EP_TD_1: {
                                    address: number,
                                    ES: number,
                                    EI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds_16: number,
                                    Milliseconds_56: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    ES: 0,
                                    EI: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0,
                                    Milliseconds_16: 0,
                                    Milliseconds_56: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                M_EP_TD_1.address = buffer.readUintBE(0, 3)
                                M_EP_TD_1.ES = ES
                                M_EP_TD_1.EI = EI
                                M_EP_TD_1.BL = BL
                                M_EP_TD_1.SB = SB
                                M_EP_TD_1.NT = NT
                                M_EP_TD_1.IV = IV
                                M_EP_TD_1.Milliseconds_16 = Milliseconds_16
                                M_EP_TD_1.Milliseconds_56 = Milliseconds_56
                                M_EP_TD_1.Minutes = Minutes
                                M_EP_TD_1.GEN = GEN
                                M_EP_TD_1.MIN_IV = MIN_IV
                                M_EP_TD_1.Hours = Hours
                                M_EP_TD_1.SU = SU
                                M_EP_TD_1.Day = Day
                                M_EP_TD_1.DOW = DOW
                                M_EP_TD_1.Month = Month
                                M_EP_TD_1.Year = Year
                                IOA_arr.push(M_EP_TD_1)
                            }
                                break
                            //带时标CP56time2a的继电器保护装置成组启动事件 M_EP_TE_1 = SPE + QDP + CP16Time2a +CP56Time2a
                            case 39: {
                                const GS: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 7, 1)
                                const SL1: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 6, 1)
                                const SL2: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 5, 1)
                                const SL3: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 4, 1)
                                const SIE: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1)
                                const SIF: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1)
                                const EI: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 4, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 4, 1, 0, 1)
                                const Milliseconds_16: number = this.readBytes(12 + (i - 1) * ioaLength + 5, 2).readUInt16LE()
                                const Milliseconds_56: number = this.readBytes(12 + (i - 1) * ioaLength + 7, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 13, 1, 1, 7)
                                const M_EP_TE_1: {
                                    address: number,
                                    GS: number,
                                    SL1: number,
                                    SL2: number,
                                    SL3: number,
                                    SIE: number,
                                    SIF: number,
                                    EI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds_16: number,
                                    Milliseconds_56: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    GS: 0,
                                    SL1: 0,
                                    SL2: 0,
                                    SL3: 0,
                                    SIE: 0,
                                    SIF: 0,
                                    EI: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0,
                                    Milliseconds_16: 0,
                                    Milliseconds_56: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                M_EP_TE_1.address = buffer.readUintBE(0, 3)
                                M_EP_TE_1.GS = GS
                                M_EP_TE_1.SL1 = SL1
                                M_EP_TE_1.SL2 = SL2
                                M_EP_TE_1.SL3 = SL3
                                M_EP_TE_1.SIE = SIE
                                M_EP_TE_1.SIF = SIF
                                M_EP_TE_1.EI = EI
                                M_EP_TE_1.BL = BL
                                M_EP_TE_1.SB = SB
                                M_EP_TE_1.NT = NT
                                M_EP_TE_1.IV = IV
                                M_EP_TE_1.Milliseconds_16 = Milliseconds_16
                                M_EP_TE_1.Milliseconds_56 = Milliseconds_56
                                M_EP_TE_1.Minutes = Minutes
                                M_EP_TE_1.GEN = GEN
                                M_EP_TE_1.MIN_IV = MIN_IV
                                M_EP_TE_1.Hours = Hours
                                M_EP_TE_1.SU = SU
                                M_EP_TE_1.Day = Day
                                M_EP_TE_1.DOW = DOW
                                M_EP_TE_1.Month = Month
                                M_EP_TE_1.Year = Year
                                IOA_arr.push(M_EP_TE_1)
                            }
                                break
                            //带时标CP56time2a的继电器保护装置成组输出电路信息 M_EP_TF_1 = OCI + CP16Time2a +CP56Time2a
                            case 40: {
                                const GC: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 7, 1)
                                const CL1: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 6, 1)
                                const CL2: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 5, 1)
                                const CL3: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 4, 1)
                                const EI: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 4, 1)
                                const BL: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1)
                                const SB: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1)
                                const NT: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 1, 1)
                                const IV: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const Milliseconds_16: number = this.readBytes(12 + (i - 1) * ioaLength + 4, 2).readUInt16LE()
                                const Milliseconds_56: number = this.readBytes(12 + (i - 1) * ioaLength + 6, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 1, 7)
                                const M_EP_TF_1: {
                                    address: number,
                                    GC: number,
                                    CL1: number,
                                    CL2: number,
                                    CL3: number,
                                    EI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds_16: number,
                                    Milliseconds_56: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    GC: 0,
                                    CL1: 0,
                                    CL2: 0,
                                    CL3: 0,
                                    EI: 0,
                                    BL: 0,
                                    SB: 0,
                                    NT: 0,
                                    IV: 0,
                                    Milliseconds_16: 0,
                                    Milliseconds_56: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                M_EP_TF_1.address = buffer.readUintBE(0, 3)
                                M_EP_TF_1.GC = GC
                                M_EP_TF_1.CL1 = CL1
                                M_EP_TF_1.CL2 = CL2
                                M_EP_TF_1.CL3 = CL3
                                M_EP_TF_1.EI = EI
                                M_EP_TF_1.BL = BL
                                M_EP_TF_1.SB = SB
                                M_EP_TF_1.NT = NT
                                M_EP_TF_1.IV = IV
                                M_EP_TF_1.Milliseconds_16 = Milliseconds_16
                                M_EP_TF_1.Milliseconds_56 = Milliseconds_56
                                M_EP_TF_1.Minutes = Minutes
                                M_EP_TF_1.GEN = GEN
                                M_EP_TF_1.MIN_IV = MIN_IV
                                M_EP_TF_1.Hours = Hours
                                M_EP_TF_1.SU = SU
                                M_EP_TF_1.Day = Day
                                M_EP_TF_1.DOW = DOW
                                M_EP_TF_1.Month = Month
                                M_EP_TF_1.Year = Year
                                IOA_arr.push(M_EP_TF_1)
                            }
                                break
                            //单命令 C_SC_NA_1 = SCO
                            case 45: {
                                const SCS: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 7, 1)
                                const QU: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 6, 1)
                                const S_OR_E: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const C_SC_NA_1: {
                                    address: number,
                                    SCS: number,
                                    QU: number,
                                    S_OR_E: number,
                                } = {
                                    address: 0,
                                    SCS: 0,
                                    QU: 0,
                                    S_OR_E: 0
                                }
                                C_SC_NA_1.address = buffer.readUintBE(0, 3)
                                C_SC_NA_1.SCS = SCS
                                C_SC_NA_1.QU = QU
                                C_SC_NA_1.S_OR_E = S_OR_E
                                IOA_arr.push(C_SC_NA_1)
                            }
                                break
                            //双命令 C_DC_NA_1 = DCO
                            case 46: {
                                const DCS: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2)
                                const S_OR_E: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const C_DC_NA_1: {
                                    address: number,
                                    DCS: number,
                                    S_OR_E: number,
                                } = {
                                    address: 0,
                                    DCS: 0,
                                    S_OR_E: 0
                                }
                                C_DC_NA_1.address = buffer.readUintBE(0, 3)
                                C_DC_NA_1.DCS = DCS
                                C_DC_NA_1.S_OR_E = S_OR_E
                                IOA_arr.push(C_DC_NA_1)
                            }
                                break
                            //步调节命令 C_RC_NA_1 = RCO
                            case 47: {
                                const RCS: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2)
                                const S_OR_E: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const C_RC_NA_1: {
                                    address: number,
                                    RCS: number,
                                    S_OR_E: number,
                                } = {
                                    address: 0,
                                    RCS: 0,
                                    S_OR_E: 0
                                }
                                C_RC_NA_1.address = buffer.readUintBE(0, 3)
                                C_RC_NA_1.RCS = RCS
                                C_RC_NA_1.S_OR_E = S_OR_E
                                IOA_arr.push(C_RC_NA_1)
                            }
                                break
                            //设点命令，归一化值 C_SE_NA_1 = NVA + QOS
                            case 48: {
                                const NVA: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUInt16LE()
                                const QL: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 1, 7)
                                const S_OR_E: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1)
                                const C_SE_NA_1: {
                                    address: number,
                                    NVA: number,
                                    QL: number,
                                    S_OR_E: number,
                                } = {
                                    address: 0,
                                    NVA: 0,
                                    QL: 0,
                                    S_OR_E: 0
                                }
                                C_SE_NA_1.address = buffer.readUintBE(0, 3)
                                C_SE_NA_1.NVA = NVA
                                C_SE_NA_1.QL = QL
                                C_SE_NA_1.S_OR_E = S_OR_E
                                IOA_arr.push(C_SE_NA_1)
                            }
                                break
                            //设点命令，标量值 C_SE_NB_1 = SVA + QOS
                            case 49: {
                                const SVA: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUInt16LE()
                                const QL: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 1, 7)
                                const S_OR_E: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1)
                                const C_SE_NB_1: {
                                    address: number,
                                    SVA: number,
                                    QL: number,
                                    S_OR_E: number,
                                } = {
                                    address: 0,
                                    SVA: 0,
                                    QL: 0,
                                    S_OR_E: 0
                                }
                                C_SE_NB_1.address = buffer.readUintBE(0, 3)
                                C_SE_NB_1.SVA = SVA
                                C_SE_NB_1.QL = QL
                                C_SE_NB_1.S_OR_E = S_OR_E
                                IOA_arr.push(C_SE_NB_1)
                            }
                                break
                            //设点命令，短浮点值 C_SE_NC_1 = IEEE STD 754 + QOS
                            case 50: {
                                const IEEE_STD_754: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 4).readFloatLE()
                                const QL: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 1, 7)
                                const S_OR_E: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const C_SE_NC_1: {
                                    address: number,
                                    IEEE_STD_754: number,
                                    QL: number,
                                    S_OR_E: number,
                                } = {
                                    address: 0,
                                    IEEE_STD_754: 0,
                                    QL: 0,
                                    S_OR_E: 0
                                }
                                C_SE_NC_1.address = buffer.readUintBE(0, 3)
                                C_SE_NC_1.IEEE_STD_754 = IEEE_STD_754
                                C_SE_NC_1.QL = QL
                                C_SE_NC_1.S_OR_E = S_OR_E
                                IOA_arr.push(C_SE_NC_1)
                            }
                                break
                            //32比特串 C_BO_NA_1 = BSI
                            case 51: {
                                const BSI: number = BufferToUInt32(this.readBytes(12 + (i - 1) * ioaLength + 3, 4))
                                const C_BO_NA_1: {
                                    address: number,
                                    BSI: number,
                                } = {
                                    address: 0,
                                    BSI: 0
                                }
                                C_BO_NA_1.address = buffer.readUintBE(0, 3)
                                C_BO_NA_1.BSI = BSI
                                IOA_arr.push(C_BO_NA_1)
                            }
                                break
                            //带时标CP56time2a的单命令 C_SC_TA_1 = SCO + CP56Time2a
                            case 58: {
                                const SCS: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 7, 1)
                                const QU: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 6, 1)
                                const S_OR_E: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 4, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 1, 7)
                                const C_SC_TA_1: {
                                    address: number,
                                    SCS: number,
                                    QU: number,
                                    S_OR_E: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    SCS: 0,
                                    QU: 0,
                                    S_OR_E: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                C_SC_TA_1.address = buffer.readUintBE(0, 3)
                                C_SC_TA_1.SCS = SCS
                                C_SC_TA_1.QU = QU
                                C_SC_TA_1.S_OR_E = S_OR_E
                                C_SC_TA_1.Milliseconds = Milliseconds
                                C_SC_TA_1.Minutes = Minutes
                                C_SC_TA_1.GEN = GEN
                                C_SC_TA_1.MIN_IV = MIN_IV
                                C_SC_TA_1.Hours = Hours
                                C_SC_TA_1.SU = SU
                                C_SC_TA_1.Day = Day
                                C_SC_TA_1.DOW = DOW
                                C_SC_TA_1.Month = Month
                                C_SC_TA_1.Year = Year
                                IOA_arr.push(C_SC_TA_1)
                            }
                                break
                            //带时标CP56time2a的双命令 C_DC_TA_1 = DCO + CP56Time2a
                            case 59: {
                                const DCS: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2)
                                const S_OR_E: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 4, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 1, 7)
                                const C_DC_TA_1: {
                                    address: number,
                                    DCS: number,
                                    S_OR_E: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    DCS: 0,
                                    S_OR_E: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                C_DC_TA_1.address = buffer.readUintBE(0, 3)
                                C_DC_TA_1.DCS = DCS
                                C_DC_TA_1.S_OR_E = S_OR_E
                                C_DC_TA_1.Milliseconds = Milliseconds
                                C_DC_TA_1.Minutes = Minutes
                                C_DC_TA_1.GEN = GEN
                                C_DC_TA_1.MIN_IV = MIN_IV
                                C_DC_TA_1.Hours = Hours
                                C_DC_TA_1.SU = SU
                                C_DC_TA_1.Day = Day
                                C_DC_TA_1.DOW = DOW
                                C_DC_TA_1.Month = Month
                                C_DC_TA_1.Year = Year
                                IOA_arr.push(C_DC_TA_1)
                            }
                                break
                            //带时标CP56time2a的步调节命令 C_RC_TA_1 = RCO + CP56Time2a
                            case 60: {
                                const RCS: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2)
                                const S_OR_E: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 4, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 1, 7)
                                const C_RC_TA_1: {
                                    address: number,
                                    RCS: number,
                                    S_OR_E: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    RCS: 0,
                                    S_OR_E: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                C_RC_TA_1.address = buffer.readUintBE(0, 3)
                                C_RC_TA_1.RCS = RCS
                                C_RC_TA_1.S_OR_E = S_OR_E
                                C_RC_TA_1.Milliseconds = Milliseconds
                                C_RC_TA_1.Minutes = Minutes
                                C_RC_TA_1.GEN = GEN
                                C_RC_TA_1.MIN_IV = MIN_IV
                                C_RC_TA_1.Hours = Hours
                                C_RC_TA_1.SU = SU
                                C_RC_TA_1.Day = Day
                                C_RC_TA_1.DOW = DOW
                                C_RC_TA_1.Month = Month
                                C_RC_TA_1.Year = Year
                                IOA_arr.push(C_RC_TA_1)
                            }
                                break
                            //带时标CP56time2a的设点命令，归一化值 C_SE_TA_1 = NVA + QOS + CP56Time2a
                            case 61: {
                                const NVA: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUInt16LE()
                                const QL: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 1, 7)
                                const S_OR_E: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 6, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 1, 7)
                                const C_SE_TA_1: {
                                    address: number,
                                    NVA: number,
                                    QL: number,
                                    S_OR_E: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    NVA: 0,
                                    QL: 0,
                                    S_OR_E: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                C_SE_TA_1.address = buffer.readUintBE(0, 3)
                                C_SE_TA_1.NVA = NVA
                                C_SE_TA_1.QL = QL
                                C_SE_TA_1.S_OR_E = S_OR_E
                                C_SE_TA_1.Milliseconds = Milliseconds
                                C_SE_TA_1.Minutes = Minutes
                                C_SE_TA_1.GEN = GEN
                                C_SE_TA_1.MIN_IV = MIN_IV
                                C_SE_TA_1.Hours = Hours
                                C_SE_TA_1.SU = SU
                                C_SE_TA_1.Day = Day
                                C_SE_TA_1.DOW = DOW
                                C_SE_TA_1.Month = Month
                                C_SE_TA_1.Year = Year
                                IOA_arr.push(C_SE_TA_1)
                            }
                                break
                            //带时标CP56time2a的设点命令，标量值 C_SE_TB_1 = SVA + QOS + CP56Time2a
                            case 62: {
                                const SVA: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUint16LE()
                                const QL: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 1, 7)
                                const S_OR_E: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 6, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 1, 7)
                                const C_SE_TB_1: {
                                    address: number,
                                    SVA: number,
                                    QL: number,
                                    S_OR_E: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    SVA: 0,
                                    QL: 0,
                                    S_OR_E: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                C_SE_TB_1.address = buffer.readUintBE(0, 3)
                                C_SE_TB_1.SVA = SVA
                                C_SE_TB_1.QL = QL
                                C_SE_TB_1.S_OR_E = S_OR_E
                                C_SE_TB_1.Milliseconds = Milliseconds
                                C_SE_TB_1.Minutes = Minutes
                                C_SE_TB_1.GEN = GEN
                                C_SE_TB_1.MIN_IV = MIN_IV
                                C_SE_TB_1.Hours = Hours
                                C_SE_TB_1.SU = SU
                                C_SE_TB_1.Day = Day
                                C_SE_TB_1.DOW = DOW
                                C_SE_TB_1.Month = Month
                                C_SE_TB_1.Year = Year
                                IOA_arr.push(C_SE_TB_1)
                            }
                                break
                            //带时标CP56time2a的设点命令，短浮点值 C_SE_TC_1 = IEEE STD 754 + QOS + CP56Time2a
                            case 63: {
                                const IEEE_STD_754: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 4).readFloatLE()
                                const QL: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 1, 7)
                                const S_OR_E: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 8, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 13, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 14, 1, 1, 7)
                                const C_SE_TC_1: {
                                    address: number,
                                    IEEE_STD_754: number,
                                    QL: number,
                                    S_OR_E: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    IEEE_STD_754: 0,
                                    QL: 0,
                                    S_OR_E: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                C_SE_TC_1.address = buffer.readUintBE(0, 3)
                                C_SE_TC_1.IEEE_STD_754 = IEEE_STD_754
                                C_SE_TC_1.QL = QL
                                C_SE_TC_1.S_OR_E = S_OR_E
                                C_SE_TC_1.Milliseconds = Milliseconds
                                C_SE_TC_1.Minutes = Minutes
                                C_SE_TC_1.GEN = GEN
                                C_SE_TC_1.MIN_IV = MIN_IV
                                C_SE_TC_1.Hours = Hours
                                C_SE_TC_1.SU = SU
                                C_SE_TC_1.Day = Day
                                C_SE_TC_1.DOW = DOW
                                C_SE_TC_1.Month = Month
                                C_SE_TC_1.Year = Year
                                IOA_arr.push(C_SE_TC_1)
                            }
                                break
                            //带时标CP56time2a的32比特串 C_BO_TA_1 = BSI + CP56Time2a
                            case 64: {
                                const BSI: number = BufferToUInt32(this.readBytes(12 + (i - 1) * ioaLength + 3, 4))
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 7, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 13, 1, 1, 7)
                                const C_SE_TC_1: {
                                    address: number,
                                    BSI: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    BSI: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                C_SE_TC_1.address = buffer.readUintBE(0, 3)
                                C_SE_TC_1.BSI = BSI
                                C_SE_TC_1.Milliseconds = Milliseconds
                                C_SE_TC_1.Minutes = Minutes
                                C_SE_TC_1.GEN = GEN
                                C_SE_TC_1.MIN_IV = MIN_IV
                                C_SE_TC_1.Hours = Hours
                                C_SE_TC_1.SU = SU
                                C_SE_TC_1.Day = Day
                                C_SE_TC_1.DOW = DOW
                                C_SE_TC_1.Month = Month
                                C_SE_TC_1.Year = Year
                                IOA_arr.push(C_SE_TC_1)
                            }
                                break
                            //初始化结束 M_EI_NA_1 = COI
                            case 70: {
                                const COI_R: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 1, 7)
                                const COI_I: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1)
                                const M_EI_NA_1: {
                                    address: number,
                                    COI_R: number,
                                    COI_I: number,
                                } = {
                                    address: 0,
                                    COI_R: 0,
                                    COI_I: 0

                                }
                                M_EI_NA_1.address = buffer.readUintBE(0, 3)
                                M_EI_NA_1.COI_R = COI_R
                                M_EI_NA_1.COI_I = COI_I
                                IOA_arr.push(M_EI_NA_1)
                            }
                                break
                            //总召唤命令 C_IC_NA_1 = QOI
                            case 100: {
                                const QOI: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 3, 1))
                                const C_IC_NA_1: {
                                    address: number,
                                    QOI: number,
                                } = {
                                    address: 0,
                                    QOI: 0
                                }
                                C_IC_NA_1.address = buffer.readUintBE(0, 3)
                                C_IC_NA_1.QOI = QOI
                                IOA_arr.push(C_IC_NA_1)
                            }
                                break
                            //电能脉冲召唤命令 C_CI_NA_1 = QCC
                            case 101: {
                                const RQT: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 2, 6)
                                const FRZ: number = this.readBits(12 + (i - 1) * ioaLength + 3, 1, 0, 2)
                                const C_CI_NA_1: {
                                    address: number,
                                    RQT: number,
                                    FRZ: number,
                                } = {
                                    address: 0,
                                    RQT: 0,
                                    FRZ: 0

                                }
                                C_CI_NA_1.address = buffer.readUintBE(0, 3)
                                C_CI_NA_1.RQT = RQT
                                C_CI_NA_1.FRZ = FRZ
                                IOA_arr.push(C_CI_NA_1)
                            }
                                break
                            //读命令 C_RD_NA_1 = NULL
                            case 102: {
                                const READ: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 3, 1))
                                const C_CI_NA_1: {
                                    address: number,
                                    READ: number,
                                } = {
                                    address: 0,
                                    READ: 0

                                }
                                C_CI_NA_1.address = buffer.readUintBE(0, 3)
                                C_CI_NA_1.READ = READ
                                IOA_arr.push(C_CI_NA_1)
                            }
                                break
                            //时钟同步命令 C_CS_NA_1 = CP56Time2a
                            case 103: {
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 1, 7)
                                const C_CS_NA_1: {
                                    address: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                C_CS_NA_1.address = buffer.readUintBE(0, 3)
                                C_CS_NA_1.Milliseconds = Milliseconds
                                C_CS_NA_1.Minutes = Minutes
                                C_CS_NA_1.GEN = GEN
                                C_CS_NA_1.MIN_IV = MIN_IV
                                C_CS_NA_1.Hours = Hours
                                C_CS_NA_1.SU = SU
                                C_CS_NA_1.Day = Day
                                C_CS_NA_1.DOW = DOW
                                C_CS_NA_1.Month = Month
                                C_CS_NA_1.Year = Year
                                IOA_arr.push(C_CS_NA_1)
                            }
                                break
                            //(IEC101)Test Command C_TS_NA_1 = FBP
                            case 104: {
                                const FBP: number = BufferToUInt16(this.readBytes(12 + (i - 1) * ioaLength + 3, 2))
                                const C_TS_NA_1: {
                                    address: number,
                                    FBP: number,
                                } = {
                                    address: 0,
                                    FBP: 0
                                }
                                C_TS_NA_1.address = buffer.readUintBE(0, 3)
                                C_TS_NA_1.FBP = FBP
                                IOA_arr.push(C_TS_NA_1)
                            }
                                break
                            //复位进程命令 C_RP_NA_1 = QRP
                            case 105: {
                                const QRP: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 3, 1))
                                const C_RP_NA_1: {
                                    address: number,
                                    QRP: number,
                                } = {
                                    address: 0,
                                    QRP: 0
                                }
                                C_RP_NA_1.address = buffer.readUintBE(0, 3)
                                C_RP_NA_1.QRP = QRP
                                IOA_arr.push(C_RP_NA_1)
                            }
                                break
                            //带时标CP56time2a的测试命令 C_TS_TA_1 = TSC + CP56time2a
                            case 107: {
                                const TSC: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 3, 1))
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 4, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 8, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 1, 7)
                                const C_TS_TA_1: {
                                    address: number,
                                    TSC: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    TSC: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                C_TS_TA_1.address = buffer.readUintBE(0, 3)
                                C_TS_TA_1.TSC = TSC
                                C_TS_TA_1.Milliseconds = Milliseconds
                                C_TS_TA_1.Minutes = Minutes
                                C_TS_TA_1.GEN = GEN
                                C_TS_TA_1.MIN_IV = MIN_IV
                                C_TS_TA_1.Hours = Hours
                                C_TS_TA_1.SU = SU
                                C_TS_TA_1.Day = Day
                                C_TS_TA_1.DOW = DOW
                                C_TS_TA_1.Month = Month
                                C_TS_TA_1.Year = Year
                                IOA_arr.push(C_TS_TA_1)
                            }
                                break
                            //归一化测量值 P_ME_NA_1 = NVA + QPM
                            case 110: {
                                const NVA: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUInt16LE()
                                const KPA: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 2, 6)
                                const POP: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1)
                                const LPC: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1)
                                const P_ME_NA_1: {
                                    address: number,
                                    NVA: number,
                                    KPA: number,
                                    POP: number,
                                    LPC: number,
                                } = {
                                    address: 0,
                                    NVA: 0,
                                    KPA: 0,
                                    POP: 0,
                                    LPC: 0
                                }
                                P_ME_NA_1.address = buffer.readUintBE(0, 3)
                                P_ME_NA_1.NVA = NVA
                                P_ME_NA_1.KPA = KPA
                                P_ME_NA_1.POP = POP
                                P_ME_NA_1.LPC = LPC
                                IOA_arr.push(P_ME_NA_1)
                            }
                                break
                            //标量化测量值 P_ME_NB_1 = SVA + QPM
                            case 111: {
                                const SVA: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUInt16LE()
                                const KPA: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 2, 6)
                                const POP: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1)
                                const LPC: number = this.readBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1)
                                const P_ME_NB_1: {
                                    address: number,
                                    SVA: number,
                                    KPA: number,
                                    POP: number,
                                    LPC: number,
                                } = {
                                    address: 0,
                                    SVA: 0,
                                    KPA: 0,
                                    POP: 0,
                                    LPC: 0
                                }
                                P_ME_NB_1.address = buffer.readUintBE(0, 3)
                                P_ME_NB_1.SVA = SVA
                                P_ME_NB_1.KPA = KPA
                                P_ME_NB_1.POP = POP
                                P_ME_NB_1.LPC = LPC
                                IOA_arr.push(P_ME_NB_1)
                            }
                                break
                            //浮点测量值 P_ME_NC_1 = IEEE STD 754 + QPM
                            case 112: {
                                const IEEE_STD_754: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 4).readFloatLE()
                                const KPA: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 2, 6)
                                const POP: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1)
                                const LPC: number = this.readBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1)
                                const P_ME_NC_1: {
                                    address: number,
                                    IEEE_STD_754: number,
                                    KPA: number,
                                    POP: number,
                                    LPC: number,
                                } = {
                                    address: 0,
                                    IEEE_STD_754: 0,
                                    KPA: 0,
                                    POP: 0,
                                    LPC: 0
                                }
                                P_ME_NC_1.address = buffer.readUintBE(0, 3)
                                P_ME_NC_1.IEEE_STD_754 = IEEE_STD_754
                                P_ME_NC_1.KPA = KPA
                                P_ME_NC_1.POP = POP
                                P_ME_NC_1.LPC = LPC
                                IOA_arr.push(P_ME_NC_1)
                            }
                                break
                            //参数激活 P_AC_NA_1 = QPA
                            case 113: {
                                const QPA: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 3, 1))
                                const P_AC_NA_1: {
                                    address: number,
                                    QPA: number,
                                } = {
                                    address: 0,
                                    QPA: 0
                                }
                                P_AC_NA_1.address = buffer.readUintBE(0, 3)
                                P_AC_NA_1.QPA = QPA
                                IOA_arr.push(P_AC_NA_1)
                            }
                                break
                            //文件已准备好 F_FR_NA_1 = NOF + LOF + FRQ
                            case 120: {
                                const NOF: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUInt16LE()
                                const LOF: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 5, 1))
                                const FRQ: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 6, 1))
                                const F_FR_NA_1: {
                                    address: number,
                                    NOF: number,
                                    LOF: number,
                                    FRQ: number,
                                } = {
                                    address: 0,
                                    NOF: 0,
                                    LOF: 0,
                                    FRQ: 0
                                }
                                F_FR_NA_1.address = buffer.readUintBE(0, 3)
                                F_FR_NA_1.NOF = NOF
                                F_FR_NA_1.LOF = LOF
                                F_FR_NA_1.FRQ = FRQ
                                IOA_arr.push(F_FR_NA_1)
                            }
                                break
                            //节点已准备好 F_SR_NA_1 = NOF + NOS + LOF + SRQ
                            case 121: {
                                const NOF: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUint16LE()
                                const NOS: number = this.readBytes(12 + (i - 1) * ioaLength + 5, 2).readUint16LE()
                                const LOF: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 7, 1))
                                const SRQ: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 8, 1))
                                const F_SR_NA_1: {
                                    address: number,
                                    NOF: number,
                                    NOS: number,
                                    LOF: number,
                                    SRQ: number,
                                } = {
                                    address: 0,
                                    NOF: 0,
                                    NOS: 0,
                                    LOF: 0,
                                    SRQ: 0
                                }
                                F_SR_NA_1.address = buffer.readUintBE(0, 3)
                                F_SR_NA_1.NOF = NOF
                                F_SR_NA_1.NOS = NOS
                                F_SR_NA_1.LOF = LOF
                                F_SR_NA_1.SRQ = SRQ
                                IOA_arr.push(F_SR_NA_1)
                            }
                                break
                            //召唤目录，选择文件，召唤文件，选择节 F_SC_NA_1 = NOF + NOS + SCQ
                            case 122: {
                                const NOF: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUint16LE()
                                const NOS: number = this.readBytes(12 + (i - 1) * ioaLength + 5, 2).readUint16LE()
                                const SCQ: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 7, 1))
                                const F_SC_NA_1: {
                                    address: number,
                                    NOF: number,
                                    NOS: number,
                                    SCQ: number,
                                } = {
                                    address: 0,
                                    NOF: 0,
                                    NOS: 0,
                                    SCQ: 0
                                }
                                F_SC_NA_1.address = buffer.readUintBE(0, 3)
                                F_SC_NA_1.NOF = NOF
                                F_SC_NA_1.NOS = NOS
                                F_SC_NA_1.SCQ = SCQ
                                IOA_arr.push(F_SC_NA_1)
                            }
                                break
                            //最后的节，最后的段 F_LS_NA_1 = NOF + NOS + LSQ + CHS
                            case 123: {
                                const NOF: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUint16LE()
                                const NOS: number = this.readBytes(12 + (i - 1) * ioaLength + 5, 2).readUint16LE()
                                const LSQ: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 7, 1))
                                const CHS: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 8, 1))
                                const F_LS_NA_1: {
                                    address: number,
                                    NOF: number,
                                    NOS: number,
                                    LSQ: number,
                                    CHS: number,
                                } = {
                                    address: 0,
                                    NOF: 0,
                                    NOS: 0,
                                    LSQ: 0,
                                    CHS: 0
                                }
                                F_LS_NA_1.address = buffer.readUintBE(0, 3)
                                F_LS_NA_1.NOF = NOF
                                F_LS_NA_1.NOS = NOS
                                F_LS_NA_1.LSQ = LSQ
                                F_LS_NA_1.CHS = CHS
                                IOA_arr.push(F_LS_NA_1)
                            }
                                break
                            //确认文件，确认节 F_FA_NA_1 = NOF + NOS + AFQ
                            case 124: {
                                const NOF: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUint16LE()
                                const NOS: number = this.readBytes(12 + (i - 1) * ioaLength + 5, 2).readUint16LE()
                                const AFQ: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 7, 1))
                                const F_FA_NA_1: {
                                    address: number,
                                    NOF: number,
                                    NOS: number,
                                    AFQ: number,
                                } = {
                                    address: 0,
                                    NOF: 0,
                                    NOS: 0,
                                    AFQ: 0
                                }
                                F_FA_NA_1.address = buffer.readUintBE(0, 3)
                                F_FA_NA_1.NOF = NOF
                                F_FA_NA_1.NOS = NOS
                                F_FA_NA_1.AFQ = AFQ
                                IOA_arr.push(F_FA_NA_1)
                            }
                                break
                            //段 F_SG_NA_1 = NOF + NOS + LOS + Segment
                            case 125: {
                                const NOF: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUint16LE()
                                const NOS: number = this.readBytes(12 + (i - 1) * ioaLength + 5, 2).readUint16LE()
                                const LOS: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 7, 1))
                                const Segment: string = BufferToHex(this.readBytes(12 + (i - 1) * ioaLength + 8, LOS))
                                const F_SG_NA_1: {
                                    address: number,
                                    NOF: number,
                                    NOS: number,
                                    LOS: number,
                                    Segment: string,
                                } = {
                                    address: 0,
                                    NOF: 0,
                                    NOS: 0,
                                    LOS: 0,
                                    Segment: '0'
                                }
                                F_SG_NA_1.address = buffer.readUintBE(0, 3)
                                F_SG_NA_1.NOF = NOF
                                F_SG_NA_1.NOS = NOS
                                F_SG_NA_1.LOS = LOS
                                F_SG_NA_1.Segment = Segment
                                IOA_arr.push(F_SG_NA_1)
                            }
                                break
                            //目录 F_DR_TA_1 = NOF + LOF + SOF + CP56Time2a
                            case 126: {
                                const NOF: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUint16LE()
                                const LOF: number = BufferToUInt16(this.readBytes(12 + (i - 1) * ioaLength + 5, 1))
                                const SOF: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 6, 1))
                                const Milliseconds: number = this.readBytes(12 + (i - 1) * ioaLength + 7, 2).readUInt16LE()
                                const Minutes: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 2, 6)
                                const GEN: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 1, 1)
                                const MIN_IV: number = this.readBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1)
                                const Hours: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5)
                                const SU: number = this.readBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1)
                                const Day: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5)
                                const DOW: number = this.readBits(12 + (i - 1) * ioaLength + 11, 1, 0, 3)
                                const Month: number = this.readBits(12 + (i - 1) * ioaLength + 12, 1, 4, 4)
                                const Year: number = this.readBits(12 + (i - 1) * ioaLength + 13, 1, 1, 7)
                                const F_DR_TA_1: {
                                    address: number,
                                    NOF: number,
                                    LOF: number,
                                    SOF: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                } = {
                                    address: 0,
                                    NOF: 0,
                                    LOF: 0,
                                    SOF: 0,
                                    Milliseconds: 0,
                                    Minutes: 0,
                                    GEN: 0,
                                    MIN_IV: 0,
                                    Hours: 0,
                                    SU: 0,
                                    Day: 0,
                                    DOW: 0,
                                    Month: 0,
                                    Year: 0
                                }
                                F_DR_TA_1.address = buffer.readUintBE(0, 3)
                                F_DR_TA_1.NOF = NOF
                                F_DR_TA_1.LOF = LOF
                                F_DR_TA_1.SOF = SOF
                                F_DR_TA_1.Milliseconds = Milliseconds
                                F_DR_TA_1.Minutes = Minutes
                                F_DR_TA_1.GEN = GEN
                                F_DR_TA_1.MIN_IV = MIN_IV
                                F_DR_TA_1.Hours = Hours
                                F_DR_TA_1.SU = SU
                                F_DR_TA_1.Day = Day
                                F_DR_TA_1.DOW = DOW
                                F_DR_TA_1.Month = Month
                                F_DR_TA_1.Year = Year
                                IOA_arr.push(F_DR_TA_1)
                            }
                                break
                            //日志查询，请求存档文件 F_SC_NB_1 = NOF + SCQ
                            case 127: {
                                const NOF: number = this.readBytes(12 + (i - 1) * ioaLength + 3, 2).readUint16LE()
                                const SCQ: number = BufferToUInt8(this.readBytes(12 + (i - 1) * ioaLength + 5, 1))
                                const F_SC_NB_1: {
                                    address: number,
                                    NOF: number,
                                    SCQ: number,
                                } = {
                                    address: 0,
                                    NOF: 0,
                                    SCQ: 0
                                }
                                F_SC_NB_1.address = buffer.readUintBE(0, 3)
                                F_SC_NB_1.NOF = NOF
                                F_SC_NB_1.SCQ = SCQ
                                IOA_arr.push(F_SC_NB_1)
                            }
                                break
                            default: {
                                this.recordError(this.instance.IOA.getPath(), 'Illegal Type Id')
                                const Data_length: number = apduLength - 4
                                const Data: string = BufferToHex(this.readBytes(6, Data_length))
                                IOA_arr.push(Data)
                                break Loop
                            }
                        }

                    }
                    this.instance.IOA.setValue(IOA_arr)
                },

                encode: (): void => {
                    const numberOfObject: number = this.instance.numberOfObject.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    const typeId: number = this.instance.messageTypeId.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    const apduLength: number = this.instance.apduLength.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    const ioaTotalLength: number = apduLength - 10
                    const ioaLength: number = ioaTotalLength / numberOfObject
                    Loop: for (let i = 1; i <= numberOfObject; i++) {
                        switch (typeId) {
                            //单点信息 M_SP_NA_1 : SIQ
                            case 1: {
                                const IOA_message: {
                                    address: number,
                                    SPI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 7, 1, IOA_message[i - 1].SPI)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].IV)
                            }
                                break
                            //双点信息 M_DP_NA_1 : DIQ
                            case 3: {
                                const IOA_message: {
                                    address: number,
                                    DPI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2, IOA_message[i - 1].DPI)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].IV)
                            }
                                break
                            //步位置信息 M_ST_NA_1 : VTI + QDS
                            case 5: {
                                const IOA_message: {
                                    address: number,
                                    VTI: number,
                                    T: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 1, 7, IOA_message[i - 1].VTI)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].T)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 7, 1, IOA_message[i - 1].OV)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 0, 1, IOA_message[i - 1].IV)
                            }
                                break
                            //32比特串 M_BO_NA_1 : BSI + QDS
                            case 7: {
                                const IOA_message: {
                                    address: number,
                                    BSI: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt32ToBuffer(IOA_message[i - 1].BSI))
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 7, 1, IOA_message[i - 1].OV)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].IV)
                            }
                                break
                            //归一化测量值 M_ME_NA_1 : NVA + QDS
                            case 9: {
                                const IOA_message: {
                                    address: number,
                                    NVA: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                const NVA_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].NVA)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(NVA_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 7, 1, IOA_message[i - 1].OV)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1, IOA_message[i - 1].IV)
                            }
                                break
                            //标量化测量值 M_ME_NB_1 : SVA + QDS
                            case 11: {
                                const IOA_message: {
                                    address: number,
                                    SVA: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                const SVA_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].SVA)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(SVA_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 7, 1, IOA_message[i - 1].OV)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1, IOA_message[i - 1].IV)
                            }
                                break
                            //浮点型测量值 M_ME_NC_1 : IEEE STD 754 + QDS
                            case 13: {
                                const IOA_message: {
                                    address: number,
                                    IEEE_STD_754: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, Float32ToBuffer(Float32ToBuffer(IOA_message[i - 1].IEEE_STD_754).readFloatLE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 7, 1, IOA_message[i - 1].OV)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].IV)
                            }
                                break
                            //累计值 M_IT_NA_1 : BCR
                            case 15: {
                                const IOA_message: {
                                    address: number,
                                    BCR: number,
                                    SQ: number,
                                    CY: number,
                                    CA: number,
                                    IV: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, Int32ToBuffer(Int32ToBuffer(IOA_message[i - 1].BCR).readInt32LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5, IOA_message[i - 1].SQ)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1, IOA_message[i - 1].CY)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1, IOA_message[i - 1].CA)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].IV)
                            }
                                break
                            //带状态检出的成组单点信息 M_PS_NA_1 : SCD + QDS
                            case 20: {
                                const IOA_message: {
                                    address: number,
                                    SCD: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt32ToBuffer(IOA_message[i - 1].SCD))
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 7, 1, IOA_message[i - 1].OV)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].IV)
                            }
                                break
                            //不带品质描述的归一化测量值 M_ME_ND_1 : NVA
                            case 21: {
                                const IOA_message: {
                                    address: number,
                                    NVA: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                const NVA_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].NVA)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(NVA_buffer.readUInt16LE()))
                            }
                                break
                            //带时标CP56time2a的单点信息 M_SP_TB_1 : SIQ + CP56Time2a
                            case 30: {
                                const IOA_message: {
                                    address: number,
                                    SPI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 7, 1, IOA_message[i - 1].SPI)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].IV)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 4, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的双点信息 M_DP_TB_1 : DIQ + CP56Time2a
                            case 31: {
                                const IOA_message: {
                                    address: number,
                                    DPI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2, IOA_message[i - 1].DPI)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 4, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].IV)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 4, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的步位置信息 M_ST_TB_1 : VTI + QDS + CP56Time2a
                            case 32: {
                                const IOA_message: {
                                    address: number,
                                    VTI: number,
                                    T: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 1, 7, IOA_message[i - 1].VTI)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].T)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 7, 1, IOA_message[i - 1].OV)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 0, 1, IOA_message[i - 1].IV)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 5, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的32比特串 M_BO_TB_1 : BSI + QDS + CP56Time2a
                            case 33: {
                                const IOA_message: {
                                    address: number,
                                    BSI: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt32ToBuffer(IOA_message[i - 1].BSI))
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 7, 1, IOA_message[i - 1].OV)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].IV)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 8, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 13, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 14, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的归一化测量值 M_ME_TD_1 = NVA + QDS +CP56Time2a
                            case 34: {
                                const IOA_message: {
                                    address: number,
                                    NVA: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                const NVA_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].NVA)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(NVA_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 7, 1, IOA_message[i - 1].OV)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1, IOA_message[i - 1].IV)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 6, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的标量化测量值 M_ME_TE_1 = SVA + QDS +CP56Time2a
                            case 35: {
                                const IOA_message: {
                                    address: number,
                                    SVA: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                const SVA_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].SVA)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(SVA_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 7, 1, IOA_message[i - 1].OV)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1, IOA_message[i - 1].IV)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 6, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的浮点型测量值 M_ME_TF_1 = IEEE STD 754 + QDS +CP56Time2a
                            case 36: {
                                const IOA_message: {
                                    address: number,
                                    IEEE_STD_754: number,
                                    OV: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, Float32ToBuffer(Float32ToBuffer(IOA_message[i - 1].IEEE_STD_754).readFloatLE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 7, 1, IOA_message[i - 1].OV)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].IV)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 8, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 13, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 14, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的累计值 M_IT_TB_1 = BCR + CP56Time2a
                            case 37: {
                                const IOA_message: {
                                    address: number,
                                    BCR: number,
                                    SQ: number,
                                    CY: number,
                                    CA: number,
                                    IV: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, Int32ToBuffer(Int32ToBuffer(IOA_message[i - 1].BCR).readInt32LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5, IOA_message[i - 1].SQ)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 2, 1, IOA_message[i - 1].CY)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1, IOA_message[i - 1].CA)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].IV)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 8, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 13, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 14, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的继电器保护装置事件 M_EP_TD_1 = QDP + CP16Time2a +CP56Time2a
                            case 38: {
                                const IOA_message: {
                                    address: number,
                                    ES: number,
                                    EI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds_16: number,
                                    Milliseconds_56: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2, IOA_message[i - 1].ES)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 4, 1, IOA_message[i - 1].EI)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].IV)
                                const Milliseconds_16_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds_16)
                                this.writeBytes(12 + (i - 1) * ioaLength + 4, UInt16ToBuffer(Milliseconds_16_buffer.readUInt16LE()))
                                const Milliseconds_56_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds_56)
                                this.writeBytes(12 + (i - 1) * ioaLength + 6, UInt16ToBuffer(Milliseconds_56_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            ////带时标CP56time2a的继电器保护装置成组启动事件 M_EP_TE_1 = SPE + QDP + CP16Time2a +CP56Time2a
                            case 39: {
                                const IOA_message: {
                                    address: number,
                                    GS: number,
                                    SL1: number,
                                    SL2: number,
                                    SL3: number,
                                    SIE: number,
                                    SIF: number,
                                    EI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds_16: number,
                                    Milliseconds_56: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 7, 1, IOA_message[i - 1].GS)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 6, 1, IOA_message[i - 1].SL1)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 5, 1, IOA_message[i - 1].SL2)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 4, 1, IOA_message[i - 1].SL3)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1, IOA_message[i - 1].SIE)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1, IOA_message[i - 1].SIF)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 4, 1, IOA_message[i - 1].EI)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 4, 1, 0, 1, IOA_message[i - 1].IV)
                                const Milliseconds_16_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds_16)
                                this.writeBytes(12 + (i - 1) * ioaLength + 5, UInt16ToBuffer(Milliseconds_16_buffer.readUInt16LE()))
                                const Milliseconds_56_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds_56)
                                this.writeBytes(12 + (i - 1) * ioaLength + 7, UInt16ToBuffer(Milliseconds_56_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 13, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的继电器保护装置成组输出电路信息 M_EP_TF_1 = OCI + CP16Time2a +CP56Time2a
                            case 40: {
                                const IOA_message: {
                                    address: number,
                                    GC: number,
                                    CL1: number,
                                    CL2: number,
                                    CL3: number,
                                    EI: number,
                                    BL: number,
                                    SB: number,
                                    NT: number,
                                    IV: number,
                                    Milliseconds_16: number,
                                    Milliseconds_56: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 7, 1, IOA_message[i - 1].GC)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 6, 1, IOA_message[i - 1].CL1)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 5, 1, IOA_message[i - 1].CL2)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 4, 1, IOA_message[i - 1].CL3)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 4, 1, IOA_message[i - 1].EI)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 3, 1, IOA_message[i - 1].BL)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 2, 1, IOA_message[i - 1].SB)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 1, 1, IOA_message[i - 1].NT)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].IV)
                                const Milliseconds_16_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds_16)
                                this.writeBytes(12 + (i - 1) * ioaLength + 4, UInt16ToBuffer(Milliseconds_16_buffer.readUInt16LE()))
                                const Milliseconds_56_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds_56)
                                this.writeBytes(12 + (i - 1) * ioaLength + 6, UInt16ToBuffer(Milliseconds_56_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //单命令 C_SC_NA_1 = SCO
                            case 45: {
                                const IOA_message: {
                                    address: number,
                                    SCS: number,
                                    QU: number,
                                    S_OR_E: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 7, 1, IOA_message[i - 1].SCS)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 6, 1, IOA_message[i - 1].QU)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].S_OR_E)
                            }
                                break
                            //双命令 C_DC_NA_1 = DCO
                            case 46: {
                                const IOA_message: {
                                    address: number,
                                    DCS: number,
                                    S_OR_E: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2, IOA_message[i - 1].DCS)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].S_OR_E)
                            }
                                break
                            //步调节命令 C_RC_NA_1 = RCO
                            case 47: {
                                const IOA_message: {
                                    address: number,
                                    RCS: number,
                                    S_OR_E: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2, IOA_message[i - 1].RCS)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].S_OR_E)
                            }
                                break
                            //设点命令，归一化值 C_SE_NA_1 = NVA + QOS
                            case 48: {
                                const IOA_message: {
                                    address: number,
                                    NVA: number,
                                    QL: number,
                                    S_OR_E: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                const NVA_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].NVA)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(NVA_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 1, 7, IOA_message[i - 1].QL)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1, IOA_message[i - 1].S_OR_E)
                            }
                                break
                            //设点命令，标量值 C_SE_NB_1 = SVA + QOS
                            case 49: {
                                const IOA_message: {
                                    address: number,
                                    SVA: number,
                                    QL: number,
                                    S_OR_E: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                const SVA_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].SVA)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(SVA_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 1, 7, IOA_message[i - 1].QL)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1, IOA_message[i - 1].S_OR_E)
                            }
                                break
                            //设点命令，短浮点值 C_SE_NC_1 = IEEE STD 754 + QOS
                            case 50: {
                                const IOA_message: {
                                    address: number,
                                    IEEE_STD_754: number,
                                    QL: number,
                                    S_OR_E: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, Float32ToBuffer(Float32ToBuffer(IOA_message[i - 1].IEEE_STD_754).readFloatLE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 1, 7, IOA_message[i - 1].QL)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].S_OR_E)
                            }
                                break
                            //32比特串 C_BO_NA_1 = BSI
                            case 51: {
                                const IOA_message: {
                                    address: number,
                                    BSI: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt32ToBuffer(IOA_message[i - 1].BSI))
                            }
                                break
                            //带时标CP56time2a的单命令 C_SC_TA_1 = SCO + CP56Time2a
                            case 58: {
                                const IOA_message: {
                                    address: number,
                                    SCS: number,
                                    QU: number,
                                    S_OR_E: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 7, 1, IOA_message[i - 1].SCS)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 6, 1, IOA_message[i - 1].QU)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].S_OR_E)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 4, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的双命令 C_DC_TA_1 = DCO + CP56Time2a
                            case 59: {
                                const IOA_message: {
                                    address: number,
                                    DCS: number,
                                    S_OR_E: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2, IOA_message[i - 1].DCS)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].S_OR_E)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 4, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的步调节命令 C_RC_TA_1 = RCO + CP56Time2a
                            case 60: {
                                const IOA_message: {
                                    address: number,
                                    RCS: number,
                                    S_OR_E: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 6, 2, IOA_message[i - 1].RCS)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].S_OR_E)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 4, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的设点命令，归一化值 C_SE_TA_1 = NVA + QOS + CP56Time2a
                            case 61: {
                                const IOA_message: {
                                    address: number,
                                    NVA: number,
                                    QL: number,
                                    S_OR_E: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                const NVA_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].NVA)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(NVA_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 1, 7, IOA_message[i - 1].QL)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1, IOA_message[i - 1].S_OR_E)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 6, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的设点命令，标量值 C_SE_TB_1 = SVA + QOS + CP56Time2a
                            case 62: {
                                const IOA_message: {
                                    address: number,
                                    SVA: number,
                                    QL: number,
                                    S_OR_E: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                const SVA_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].SVA)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(SVA_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 1, 7, IOA_message[i - 1].QL)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1, IOA_message[i - 1].S_OR_E)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 6, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的设点命令，短浮点值 C_SE_TC_1 = IEEE STD 754 + QOS + CP56Time2a
                            case 63: {
                                const IOA_message: {
                                    address: number,
                                    IEEE_STD_754: number,
                                    QL: number,
                                    S_OR_E: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, Float32ToBuffer(Float32ToBuffer(IOA_message[i - 1].IEEE_STD_754).readFloatLE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 1, 7, IOA_message[i - 1].QL)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].S_OR_E)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 8, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 13, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 14, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //带时标CP56time2a的32比特串 C_BO_TA_1 = BSI + CP56Time2a
                            case 64: {
                                const IOA_message: {
                                    address: number,
                                    BSI: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt32ToBuffer(IOA_message[i - 1].BSI))
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 7, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 13, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //初始化结束 M_EI_NA_1 = COI
                            case 70: {
                                const IOA_message: {
                                    address: number,
                                    COI_R: number,
                                    COI_I: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 1, 7, IOA_message[i - 1].COI_R)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 1, IOA_message[i - 1].COI_I)
                            }
                                break
                            //总召唤命令 C_IC_NA_1 = QOI
                            case 100: {
                                const IOA_message: {
                                    address: number,
                                    QOI: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt8ToBuffer(IOA_message[i - 1].QOI))
                            }
                                break
                            //电能脉冲召唤命令 C_CI_NA_1 = QCC
                            case 101: {
                                const IOA_message: {
                                    address: number,
                                    RQT: number,
                                    FRZ: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 2, 6, IOA_message[i - 1].RQT)
                                this.writeBits(12 + (i - 1) * ioaLength + 3, 1, 0, 2, IOA_message[i - 1].FRZ)
                            }
                                break
                            //读命令 C_RD_NA_1 = NULL
                            case 102: {
                                const IOA_message: {
                                    address: number,
                                    READ: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt8ToBuffer(IOA_message[i - 1].READ))
                            }
                                break
                            //时钟同步命令 C_CS_NA_1 = CP56Time2a
                            case 103: {
                                const IOA_message: {
                                    address: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //(IEC101)Test Command C_TS_NA_1 = FBP
                            case 104: {
                                const IOA_message: {
                                    address: number,
                                    FBP: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(IOA_message[i - 1].FBP))
                            }
                                break
                            //复位进程命令 C_RP_NA_1 = QRP
                            case 105: {
                                const IOA_message: {
                                    address: number,
                                    QRP: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt8ToBuffer(IOA_message[i - 1].QRP))
                            }
                                break
                            //带时标CP56time2a的测试命令 C_TS_TA_1 = TSC + CP56time2a
                            case 107: {
                                const IOA_message: {
                                    address: number,
                                    TSC: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt8ToBuffer(IOA_message[i - 1].TSC))
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 4, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 6, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 8, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //归一化测量值 P_ME_NA_1 = NVA + QPM
                            case 110: {
                                const IOA_message: {
                                    address: number,
                                    NVA: number,
                                    KPA: number,
                                    POP: number,
                                    LPC: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                const NVA_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].NVA)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(NVA_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 2, 6, IOA_message[i - 1].KPA)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1, IOA_message[i - 1].POP)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1, IOA_message[i - 1].LPC)
                            }
                                break
                            //标量化测量值 P_ME_NB_1 = SVA + QPM
                            case 111: {
                                const IOA_message: {
                                    address: number,
                                    SVA: number,
                                    KPA: number,
                                    POP: number,
                                    LPC: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                const SVA_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].SVA)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(SVA_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 2, 6, IOA_message[i - 1].KPA)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 1, 1, IOA_message[i - 1].POP)
                                this.writeBits(12 + (i - 1) * ioaLength + 5, 1, 0, 1, IOA_message[i - 1].LPC)
                            }
                                break
                            //浮点测量值 P_ME_NC_1 = IEEE STD 754 + QPM
                            case 112: {
                                const IOA_message: {
                                    address: number,
                                    IEEE_STD_754: number,
                                    KPA: number,
                                    POP: number,
                                    LPC: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, Float32ToBuffer(Float32ToBuffer(IOA_message[i - 1].IEEE_STD_754).readFloatLE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 2, 6, IOA_message[i - 1].KPA)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 1, 1, IOA_message[i - 1].POP)
                                this.writeBits(12 + (i - 1) * ioaLength + 7, 1, 0, 1, IOA_message[i - 1].LPC)
                            }
                                break
                            //参数激活 P_AC_NA_1 = QPA
                            case 113: {
                                const IOA_message: {
                                    address: number,
                                    QPA: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt8ToBuffer(IOA_message[i - 1].QPA))
                            }
                                break
                            //文件已准备好 F_FR_NA_1 = NOF + LOF + FRQ
                            case 120: {
                                const IOA_message: {
                                    address: number,
                                    NOF: number,
                                    LOF: number,
                                    FRQ: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(UInt16ToBuffer(IOA_message[i - 1].NOF).readUInt16LE()))
                                this.writeBytes(12 + (i - 1) * ioaLength + 5, UInt8ToBuffer(IOA_message[i - 1].LOF))
                                this.writeBytes(12 + (i - 1) * ioaLength + 6, UInt8ToBuffer(IOA_message[i - 1].FRQ))
                            }
                                break
                            //节点已准备好 F_SR_NA_1 = NOF + NOS + LOF + SRQ
                            case 121: {
                                const IOA_message: {
                                    address: number,
                                    NOF: number,
                                    NOS: number,
                                    LOF: number,
                                    SRQ: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(UInt16ToBuffer(IOA_message[i - 1].NOF).readUInt16LE()))
                                this.writeBytes(12 + (i - 1) * ioaLength + 5, UInt16ToBuffer(UInt16ToBuffer(IOA_message[i - 1].NOS).readUInt16LE()))
                                this.writeBytes(12 + (i - 1) * ioaLength + 7, UInt8ToBuffer(IOA_message[i - 1].LOF))
                                this.writeBytes(12 + (i - 1) * ioaLength + 8, UInt8ToBuffer(IOA_message[i - 1].SRQ))
                            }
                                break
                            //召唤目录，选择文件，召唤文件，选择节 F_SC_NA_1 = NOF + NOS + SCQ
                            case 122: {
                                const IOA_message: {
                                    address: number,
                                    NOF: number,
                                    NOS: number,
                                    SCQ: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(IOA_message[i - 1].NOF))
                                this.writeBytes(12 + (i - 1) * ioaLength + 5, UInt16ToBuffer(UInt16ToBuffer(IOA_message[i - 1].NOS).readUInt16LE()))
                                this.writeBytes(12 + (i - 1) * ioaLength + 7, UInt8ToBuffer(IOA_message[i - 1].SCQ))
                            }
                                break
                            //最后的节，最后的段 F_LS_NA_1 = NOF + NOS + LSQ + CHS
                            case 123: {
                                const IOA_message: {
                                    address: number,
                                    NOF: number,
                                    NOS: number,
                                    LSQ: number,
                                    CHS: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(UInt16ToBuffer(IOA_message[i - 1].NOF).readUInt16LE()))
                                this.writeBytes(12 + (i - 1) * ioaLength + 5, UInt16ToBuffer(IOA_message[i - 1].NOS))
                                this.writeBytes(12 + (i - 1) * ioaLength + 7, UInt8ToBuffer(IOA_message[i - 1].LSQ))
                                this.writeBytes(12 + (i - 1) * ioaLength + 8, UInt8ToBuffer(IOA_message[i - 1].CHS))
                            }
                                break
                            //确认文件，确认节 F_FA_NA_1 = NOF + NOS + AFQ
                            case 124: {
                                const IOA_message: {
                                    address: number,
                                    NOF: number,
                                    NOS: number,
                                    AFQ: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(UInt16ToBuffer(IOA_message[i - 1].NOF).readUInt16LE()))
                                this.writeBytes(12 + (i - 1) * ioaLength + 5, UInt16ToBuffer(UInt16ToBuffer(IOA_message[i - 1].NOS).readUInt16LE()))
                                this.writeBytes(12 + (i - 1) * ioaLength + 7, UInt8ToBuffer(IOA_message[i - 1].AFQ))
                            }
                                break
                            //段 F_SG_NA_1 = NOF + NOS + LOS + Segment
                            case 125: {
                                const IOA_message: {
                                    address: number,
                                    NOF: number,
                                    NOS: number,
                                    LOS: number,
                                    Segment: string,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(UInt16ToBuffer(IOA_message[i - 1].NOF).readUInt16LE()))
                                this.writeBytes(12 + (i - 1) * ioaLength + 5, UInt16ToBuffer(UInt16ToBuffer(IOA_message[i - 1].NOS).readUInt16LE()))
                                this.writeBytes(12 + (i - 1) * ioaLength + 7, UInt8ToBuffer(IOA_message[i - 1].LOS))
                                this.writeBytes(12 + (i - 1) * ioaLength + 8, HexToBuffer(IOA_message[i - 1].Segment))
                            }
                                break
                            //目录 F_DR_TA_1 = NOF + LOF + SOF + CP56Time2a
                            case 126: {
                                const IOA_message: {
                                    address: number,
                                    NOF: number,
                                    LOF: number,
                                    SOF: number,
                                    Milliseconds: number,
                                    Minutes: number,
                                    GEN: number,
                                    MIN_IV: number,
                                    Hours: number,
                                    SU: number,
                                    Day: number,
                                    DOW: number,
                                    Month: number,
                                    Year: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(UInt16ToBuffer(IOA_message[i - 1].NOF).readUInt16LE()))
                                this.writeBytes(12 + (i - 1) * ioaLength + 5, UInt8ToBuffer(IOA_message[i - 1].LOF))
                                this.writeBytes(12 + (i - 1) * ioaLength + 6, UInt8ToBuffer(IOA_message[i - 1].SOF))
                                const Milliseconds_buffer: Buffer = UInt16ToBuffer(IOA_message[i - 1].Milliseconds)
                                this.writeBytes(12 + (i - 1) * ioaLength + 7, UInt16ToBuffer(Milliseconds_buffer.readUInt16LE()))
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 2, 6, IOA_message[i - 1].Minutes)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 1, 1, IOA_message[i - 1].GEN)
                                this.writeBits(12 + (i - 1) * ioaLength + 9, 1, 0, 1, IOA_message[i - 1].MIN_IV)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 3, 5, IOA_message[i - 1].Hours)
                                this.writeBits(12 + (i - 1) * ioaLength + 10, 1, 0, 1, IOA_message[i - 1].SU)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 3, 5, IOA_message[i - 1].Day)
                                this.writeBits(12 + (i - 1) * ioaLength + 11, 1, 0, 3, IOA_message[i - 1].DOW)
                                this.writeBits(12 + (i - 1) * ioaLength + 12, 1, 4, 4, IOA_message[i - 1].Month)
                                this.writeBits(12 + (i - 1) * ioaLength + 13, 1, 1, 7, IOA_message[i - 1].Year)
                            }
                                break
                            //日志查询，请求存档文件 F_SC_NB_1 = NOF + SCQ
                            case 127: {
                                const IOA_message: {
                                    address: number,
                                    NOF: number,
                                    SCQ: number,
                                }[] = this.instance.IOA.getValue([], (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                const address_LE: number = IOA_message[i - 1].address
                                const buf = Buffer.alloc(3)
                                buf.writeUIntLE(address_LE, 0, 3)
                                this.writeBytes(12 + (i - 1) * ioaLength, buf)
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt16ToBuffer(UInt16ToBuffer(IOA_message[i - 1].NOF).readInt16LE()))
                                this.writeBytes(12 + (i - 1) * ioaLength + 3, UInt8ToBuffer(IOA_message[i - 1].SCQ))
                            }
                                break
                            default: {
                                const Data: string = this.instance.IOA.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                                this.writeBytes(6, HexToBuffer(Data))
                                break Loop
                            }
                        }
                    }

                }
            }

        }
    }
    public id: string = 'IEC104_I_Frame'
    public name: string = 'IEC 60870-5-104'
    public nickname: string = 'iec60870_104'

    public match(): boolean {
        if (!this.prevCodecModules) return false
        if (BufferToUInt8(this.readBytes(0, 1)) != 104) return false
        const type: number = this.readBits(2, 1, 6, 2)
        switch (type) {
            case 0: {
                return true
            }
            case 2: {
                return true
            }
            default: {
                return false
            }
        }
    };
}