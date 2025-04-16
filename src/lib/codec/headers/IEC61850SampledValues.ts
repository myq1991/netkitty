import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import TLV from 'node-tlv'
import {HexToUInt16} from '../../helper/HexToNumber'
import {UInt16ToBERHex} from '../../helper/NumberToBERHex'
import {UInt16ToHex, UInt32ToHex, UInt8ToHex} from '../../helper/NumberToHex'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {BufferToUInt16, BufferToUInt32, BufferToUInt64, BufferToUInt8} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'

type ASDUItem = {
    svID: string
    dataSet?: string
    smpCnt: number
    confRev: number
    refrTm?: string
    smpSynch: number
    smpRate?: number
    sample: string
    smpMod?: number
}

export class IEC61850SampledValues extends BaseHeader {

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
            svPdu: {
                type: 'object',
                label: 'Sampled Values PDU',
                decode: (): void => {
                    const buffer: Buffer = this.readBytes(8, (this.instance.length.getValue()) - 8)
                    this.TLVInstance = TLV.parse(buffer)
                    this.TLVChild = this.TLVInstance.getChild()
                    this.instance.svPdu.setValue({})
                },
                encode: (): void => {
                    let buffer: Buffer = Buffer.from([])
                    this.TLVChild.forEach(TLVItem => buffer = Buffer.concat([buffer, TLVItem.bTag, TLVItem.bLength, TLVItem.bValue]))
                    const svPduTLV: TLV = new TLV(0x60, buffer)
                    const svPduBuffer: Buffer = Buffer.concat([svPduTLV.bTag, svPduTLV.bLength, svPduTLV.bValue])
                    this.writeBytes(8, svPduBuffer)
                    /**
                     * Update the length only if it is not set
                     * Update length(APPID's length + Length's length + Reserved1's length + Reserved2's length + svPdu's length)
                     */
                    if (this.instance.length.getValue() > 0) return
                    this.instance.length.setValue(2 + 2 + 2 + 2 + svPduBuffer.length)
                },
                properties: {
                    noASDU: {
                        type: 'integer',
                        minimum: 1,
                        maximum: 65535,
                        label: 'Number of ASDU',
                        decode: (): void => {
                            const noASDUTLV: TLV | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x80)
                            if (!noASDUTLV) return this.recordError(this.instance.svPdu.noASDU.getPath(), 'Not Found')
                            const noASDUNum: number = HexToUInt16(noASDUTLV.getValue('hex'))
                            if (!noASDUNum) this.recordError(this.instance.svPdu.noASDU.getPath(), 'Number of ASDU should be greater or equal to 1')
                            this.instance.svPdu.noASDU.setValue(noASDUNum)
                        },
                        encode: (): void => {
                            const noASDU: number = this.instance.svPdu.noASDU.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'noASDU is not set'))
                            this.TLVChild.push(new TLV(0x80, UInt16ToBERHex(noASDU)))
                        }
                    },
                    seqASDU: {
                        type: 'array',
                        label: 'Sequence ASDU',
                        items: {
                            type: 'object',
                            properties: {
                                svID: {
                                    type: 'string',
                                    contentEncoding: StringContentEncodingEnum.ASCII,
                                    label: 'SvID'
                                },
                                dataSet: {
                                    type: 'string',
                                    contentEncoding: StringContentEncodingEnum.ASCII,
                                    label: 'DatSet'
                                },
                                smpCnt: {
                                    type: 'integer',
                                    label: 'SmpCnt'
                                },
                                confRev: {
                                    type: 'integer',
                                    label: 'ConfRev'
                                },
                                refrTm: {
                                    type: 'string',
                                    contentEncoding: StringContentEncodingEnum.BIGINT,
                                    label: 'RefrTm'
                                },
                                smpSynch: {
                                    type: 'integer',
                                    label: 'SmpSynch'
                                },
                                smpRate: {
                                    type: 'integer',
                                    label: 'SmpRate'
                                },
                                sample: {
                                    type: 'string',
                                    contentEncoding: StringContentEncodingEnum.HEX,
                                    label: 'Sample'
                                },
                                smpMod: {
                                    type: 'integer',
                                    label: 'SmpMod'
                                }
                            }
                        },
                        decode: (): void => {
                            const seqASDU: ASDUItem[] = []
                            const seqASDUTLV: TLV | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0xa2)
                            if (!seqASDUTLV) {
                                this.instance.svPdu.seqASDU.setValue(seqASDU)
                                return
                            }
                            const ASDUTLVs: TLV[] = seqASDUTLV.getChild()
                            ASDUTLVs.forEach((ASDUTLV: TLV, index: number): void => {
                                const errorNodePath: string = this.instance.svPdu.seqASDU.getPath(index)
                                if (ASDUTLV.getTag('number') !== 0x30) this.recordError(errorNodePath, 'Invalid ASDU item tag')
                                const ASDUAttributeTLVs: TLV[] = ASDUTLV.getChild()
                                let svID: string
                                let dataSet: string
                                let smpCnt: number
                                let confRev: number
                                let refrTm: string
                                let smpSynch: number
                                let smpRate: number
                                let sample: string
                                let smpMod: number
                                //svID
                                const svIDTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x80)
                                if (svIDTLV) {
                                    svID = svIDTLV.getValue('buffer').toString('ascii')
                                } else {
                                    this.recordError(errorNodePath, 'svID Not Found')
                                }
                                //dataSet (optional)
                                const dataSetTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x81)
                                if (dataSetTLV) {
                                    dataSet = dataSetTLV.getValue('buffer').toString('ascii')
                                }
                                //smpCnt
                                const smpCntTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x82)
                                if (smpCntTLV) {
                                    smpCnt = BufferToUInt16(smpCntTLV.getValue('buffer'))
                                } else {
                                    this.recordError(errorNodePath, 'smpCnt Not Found')
                                }
                                //confRev
                                const confRevTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x83)
                                if (confRevTLV) {
                                    confRev = BufferToUInt32(confRevTLV.getValue('buffer'))
                                } else {
                                    this.recordError(errorNodePath, 'confRev Not Found')
                                }
                                //refrTm (optional)
                                const refrTmTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x84)
                                if (refrTmTLV) {
                                    refrTm = BufferToUInt64(refrTmTLV.getValue('buffer')).toString()
                                }
                                //smpSynch
                                const smpSynchTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x85)
                                if (smpSynchTLV) {
                                    smpSynch = BufferToUInt8(smpSynchTLV.getValue('buffer'))
                                } else {
                                    this.recordError(errorNodePath, 'smpSynch Not Found')
                                }
                                //smpRate (optional)
                                const smpRateTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x86)
                                if (smpRateTLV) {
                                    smpRate = BufferToUInt16(smpRateTLV.getValue('buffer'))
                                }
                                //sample
                                const sampleTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x87)
                                if (sampleTLV) {
                                    sample = sampleTLV.getValue('hex')
                                } else {
                                    this.recordError(errorNodePath, 'sample Not Found')
                                }
                                //smpMod (optional)
                                const smpModTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x86)
                                if (smpModTLV) {
                                    smpMod = BufferToUInt16(smpModTLV.getValue('buffer'))
                                }
                                seqASDU.push({
                                    svID: svID!,
                                    dataSet: dataSet!,
                                    smpCnt: smpCnt!,
                                    confRev: confRev!,
                                    refrTm: refrTm!,
                                    smpSynch: smpSynch!,
                                    smpRate: smpRate!,
                                    sample: sample!,
                                    smpMod: smpMod!
                                })
                            })
                            this.instance.svPdu.seqASDU.setValue(seqASDU)
                        },
                        encode: (): void => {
                            const seqASDU: ASDUItem[] = this.instance.svPdu.seqASDU.isUndefined() ? [] : this.instance.svPdu.seqASDU.getValue()
                            const seqASDUTLVs: TLV[] = []
                            seqASDU.forEach((seqASDUItem: ASDUItem, index: number): void => {
                                const errorNodePath: string = this.instance.svPdu.seqASDU.getPath(index)
                                const seqASDUItemTLVs: TLV[] = []
                                //svID
                                if (seqASDUItem.svID !== undefined) {
                                    seqASDUItemTLVs.push(new TLV(0x80, Buffer.from(seqASDUItem.svID ? seqASDUItem.svID : '', 'ascii')))
                                } else {
                                    this.recordError(errorNodePath, 'No svID')
                                }
                                //dataSet
                                if (seqASDUItem.dataSet !== undefined) seqASDUItemTLVs.push(new TLV(0x81, Buffer.from(seqASDUItem.dataSet ? seqASDUItem.dataSet : '', 'ascii')))
                                // smpCnt
                                if (seqASDUItem.smpCnt !== undefined) {
                                    seqASDUItemTLVs.push(new TLV(0x82, UInt16ToHex(seqASDUItem.smpCnt)))
                                } else {
                                    this.recordError(errorNodePath, 'No smpCnt')
                                }
                                // confRev
                                if (seqASDUItem.confRev !== undefined) {
                                    seqASDUItemTLVs.push(new TLV(0x83, UInt32ToHex(seqASDUItem.confRev)))
                                } else {
                                    this.recordError(errorNodePath, 'No confRev')
                                }
                                // refrTm
                                if (seqASDUItem.refrTm !== undefined) seqASDUItemTLVs.push(new TLV(0x84, Buffer.from(BigInt(seqASDUItem.refrTm).toString(16).padStart(8 * 2, '0'), 'hex')))
                                // smpSynch
                                if (seqASDUItem.smpSynch !== undefined) {
                                    seqASDUItemTLVs.push(new TLV(0x85, UInt8ToHex(seqASDUItem.smpSynch)))
                                } else {
                                    this.recordError(errorNodePath, 'No smpSynch')
                                }
                                // smpRate
                                if (seqASDUItem.smpRate !== undefined) seqASDUItemTLVs.push(new TLV(0x86, UInt16ToHex(seqASDUItem.smpRate)))
                                // sample
                                if (seqASDUItem.sample !== undefined) {
                                    seqASDUItemTLVs.push(new TLV(0x87, Buffer.from(seqASDUItem.sample, 'hex')))
                                } else {
                                    this.recordError(errorNodePath, 'No sample')
                                }
                                // smpMod
                                if (seqASDUItem.smpMod !== undefined) seqASDUItemTLVs.push(new TLV(0x88, UInt16ToHex(seqASDUItem.smpMod)))
                                if (!seqASDUItemTLVs.length) return
                                let seqASDUItemBuffer: Buffer = Buffer.from([])
                                seqASDUItemTLVs.forEach(seqASDUItemTLV => seqASDUItemBuffer = Buffer.concat([seqASDUItemBuffer, seqASDUItemTLV.bTag, seqASDUItemTLV.bLength, seqASDUItemTLV.bValue]))
                                seqASDUTLVs.push(new TLV(0x30, seqASDUItemBuffer))
                            })
                            let seqASDUBuffer: Buffer = Buffer.from([])
                            seqASDUTLVs.forEach(seqASDUTLV => seqASDUBuffer = Buffer.concat([seqASDUBuffer, seqASDUTLV.bTag, seqASDUTLV.bLength, seqASDUTLV.bValue]))
                            this.TLVChild.push(new TLV(0xa2, seqASDUBuffer))
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'sv'

    public readonly name: string = 'IEC61850 Sampled Values'

    public readonly nickname: string = 'SV'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.etherType.getValue() === UInt16ToHex(0x88ba)
    }
}
