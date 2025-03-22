import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import TLV from 'node-tlv'
import {HexToUInt16, HexToUInt32, HexToUInt8} from '../lib/HexToNumber'
import {UInt16ToBERHex} from '../lib/NumberToBERHex'
import {UInt16ToHex, UInt32ToHex, UInt8ToHex} from '../lib/NumberToHex'

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

export default class IEC61850SampledValues extends BaseHeader {

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
                    this.instance.appid = parseInt(this.readBytes(0, 2).toString('hex'), 16)
                },
                encode: (): void => {
                    let APPID: number = parseInt(this.instance.appid.toString())
                    APPID = APPID ? APPID : 0
                    this.writeBytes(0, Buffer.from(APPID.toString(16).padStart(4, '0'), 'hex'))
                }
            },
            length: {
                type: 'integer',
                label: 'Length',
                decode: (): void => {
                    this.instance.length = parseInt(this.readBytes(2, 2).toString('hex'), 16)
                    if (this.instance.length === undefined) this.recordError('length', 'Not Found')
                },
                encode: (): void => {
                    let length: number = parseInt(this.instance.length.toString())
                    length = length ? length : 0
                    this.writeBytes(2, Buffer.from(length.toString(16).padStart(4, '0'), 'hex'))
                }
            },
            reserved1: {
                type: 'object',
                label: 'Reserved1',
                decode: (): void => {
                    this.instance.reserved1 = {}
                },
                properties: {
                    simulated: {
                        type: 'boolean',
                        label: 'Simulated',
                        decode: (): void => {
                            this.instance.reserved1['simulated'] = !!this.readBits(4, 2, 0, 1)
                        },
                        encode: (): void => {
                            const simulated: boolean = !!this.instance.reserved1['simulated']
                            this.writeBits(4, 2, 0, 1, simulated ? 1 : 0)
                        }
                    },
                    reserved: {
                        type: 'number',
                        minimum: 0,
                        maximum: 32767,
                        label: 'Reserved',
                        decode: (): void => {
                            this.instance.reserved1['reserved'] = this.readBits(4, 2, 1, 16)
                        },
                        encode: (): void => {
                            let reserved: number = parseInt(this.instance.reserved1['reserved'].toString())
                            reserved = reserved ? reserved : 0
                            this.writeBits(4, 2, 1, 16, reserved)
                        }
                    }
                }
            },
            reserved2: {
                type: 'object',
                label: 'Reserved2',
                decode: (): void => {
                    this.instance.reserved2 = {}
                },
                properties: {
                    reserved: {
                        type: 'number',
                        minimum: 0,
                        maximum: 65535,
                        label: 'Reserved',
                        decode: (): void => {
                            this.instance.reserved2['reserved'] = this.readBits(4, 2, 0, 16)
                        },
                        encode: (): void => {
                            let reserved: number = parseInt(this.instance.reserved2['reserved'].toString())
                            reserved = reserved ? reserved : 0
                            this.writeBits(4, 2, 0, 16, reserved)
                        }
                    }
                }
            },
            svPdu: {
                type: 'object',
                label: 'Sampled Values PDU',
                decode: (): void => {
                    const buffer: Buffer = this.readBytes(8, (this.instance.length as number) - 8)
                    this.TLVInstance = TLV.parse(buffer)
                    this.TLVChild = this.TLVInstance.getChild()
                    this.instance.svPdu = {}
                },
                encode: (): void => {
                    let buffer: Buffer = Buffer.from([])
                    this.TLVChild.forEach(TLVItem => buffer = Buffer.concat([buffer, TLVItem.bTag, TLVItem.bLength, TLVItem.bValue]))
                    const svPduTLV: TLV = new TLV(0x60, buffer)
                    let svPduBuffer: Buffer = Buffer.concat([svPduTLV.bTag, svPduTLV.bLength, svPduTLV.bValue])
                    this.writeBytes(8, svPduBuffer)
                    /**
                     * Update the length only if it is not set
                     * Update length(APPID's length + Length's length + Reserved1's length + Reserved2's length + svPdu's length)
                     */
                    if (this.instance.length as number > 0) return
                    this.instance.length = 2 + 2 + 2 + 2 + svPduBuffer.length
                    this.SCHEMA.properties!['length']!['encode']!()
                },
                properties: {
                    noASDU: {
                        type: 'integer',
                        minimum: 1,
                        maximum: 65535,
                        label: 'Number of ASDU',
                        decode: (): void => {
                            const noASDUTLV: TLV | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x80)
                            if (!noASDUTLV) return this.recordError('svPdu.noASDU', 'Not Found')
                            const noASDUNum: number = HexToUInt16(noASDUTLV.getValue('hex'))
                            if (!noASDUNum) this.recordError('svPdu.noASDU', 'Number of ASDU should be greater or equal to 1')
                            this.instance.svPdu['noASDU'] = noASDUNum
                        },
                        encode: (): void => {
                            if (this.instance.svPdu['noASDU'] === undefined) this.recordError('svPdu.noASDU', 'noASDU is not set')
                            this.TLVChild.push(new TLV(0x80, UInt16ToBERHex(parseInt(this.instance.svPdu['noASDU'].toString()))))
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
                                    label: 'SvID'
                                },
                                dataSet: {
                                    type: 'string',
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
                                this.instance.svPdu['seqASDU'] = seqASDU
                                return
                            }
                            const ASDUTLVs: TLV[] = seqASDUTLV.getChild()
                            ASDUTLVs.forEach((ASDUTLV: TLV, index: number): void => {
                                if (ASDUTLV.getTag('number') !== 0x30) this.recordError(`svPdu.seqASDU[${index}]`, 'Invalid ASDU item tag')
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
                                    this.recordError(`svPdu.seqASDU[${index}]`, 'svID Not Found')
                                }
                                //dataSet (optional)
                                const dataSetTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x81)
                                if (dataSetTLV) {
                                    dataSet = dataSetTLV.getValue('buffer').toString('ascii')
                                }
                                //smpCnt
                                const smpCntTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x82)
                                if (smpCntTLV) {
                                    smpCnt = HexToUInt16(smpCntTLV.getValue('buffer').toString('hex'))
                                } else {
                                    this.recordError(`svPdu.seqASDU[${index}]`, 'smpCnt Not Found')
                                }
                                //confRev
                                const confRevTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x83)
                                if (confRevTLV) {
                                    confRev = HexToUInt32(confRevTLV.getValue('buffer').toString('hex'))
                                } else {
                                    this.recordError(`svPdu.seqASDU[${index}]`, 'confRev Not Found')
                                }
                                //refrTm (optional)
                                const refrTmTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x84)
                                if (refrTmTLV) {
                                    refrTm = BigInt(`0x${refrTmTLV.getValue('hex')}`).toString()
                                }
                                //smpSynch
                                const smpSynchTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x85)
                                if (smpSynchTLV) {
                                    smpSynch = HexToUInt8(smpSynchTLV.getValue('buffer').toString('hex'))
                                } else {
                                    this.recordError(`svPdu.seqASDU[${index}]`, 'smpSynch Not Found')
                                }
                                //smpRate (optional)
                                const smpRateTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x86)
                                if (smpRateTLV) {
                                    smpRate = HexToUInt16(smpRateTLV.getValue('buffer').toString('hex'))
                                }
                                //sample
                                const sampleTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x87)
                                if (sampleTLV) {
                                    sample = sampleTLV.getValue('hex')
                                } else {
                                    this.recordError(`svPdu.seqASDU[${index}]`, 'sample Not Found')
                                }
                                //smpMod (optional)
                                const smpModTLV: TLV | undefined = ASDUAttributeTLVs.find(tlv => tlv.getTag('number') === 0x86)
                                if (smpModTLV) {
                                    smpMod = HexToUInt16(smpModTLV.getValue('buffer').toString('hex'))
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
                            this.instance.svPdu['seqASDU'] = seqASDU
                        },
                        encode: (): void => {
                            const seqASDU: ASDUItem[] = this.instance.svPdu['seqASDU'] ? this.instance.svPdu['seqASDU'] : []
                            const seqASDUTLVs: TLV[] = []
                            seqASDU.forEach((seqASDUItem: ASDUItem, index: number): void => {
                                const seqASDUItemTLVs: TLV[] = []
                                //svID
                                if (seqASDUItem.svID !== undefined) {
                                    seqASDUItemTLVs.push(new TLV(0x80, Buffer.from(seqASDUItem.svID ? seqASDUItem.svID : '', 'ascii')))
                                } else {
                                    this.recordError(`svPdu.seqASDU[${index}]`, 'No svID')
                                }
                                //dataSet
                                if (seqASDUItem.dataSet !== undefined) seqASDUItemTLVs.push(new TLV(0x81, Buffer.from(seqASDUItem.dataSet ? seqASDUItem.dataSet : '', 'ascii')))
                                // smpCnt
                                if (seqASDUItem.smpCnt !== undefined) {
                                    seqASDUItemTLVs.push(new TLV(0x82, UInt16ToHex(seqASDUItem.smpCnt)))
                                } else {
                                    this.recordError(`svPdu.seqASDU[${index}]`, 'No smpCnt')
                                }
                                // confRev
                                if (seqASDUItem.confRev !== undefined) {
                                    seqASDUItemTLVs.push(new TLV(0x83, UInt32ToHex(seqASDUItem.confRev)))
                                } else {
                                    this.recordError(`svPdu.seqASDU[${index}]`, 'No confRev')
                                }
                                // refrTm
                                if (seqASDUItem.refrTm !== undefined) seqASDUItemTLVs.push(new TLV(0x84, Buffer.from(BigInt(seqASDUItem.refrTm).toString(16).padStart(8 * 2, '0'), 'hex')))
                                // smpSynch
                                if (seqASDUItem.smpSynch !== undefined) {
                                    seqASDUItemTLVs.push(new TLV(0x85, UInt8ToHex(seqASDUItem.smpSynch)))
                                } else {
                                    this.recordError(`svPdu.seqASDU[${index}]`, 'No smpSynch')
                                }
                                // smpRate
                                if (seqASDUItem.smpRate !== undefined) seqASDUItemTLVs.push(new TLV(0x86, UInt16ToHex(seqASDUItem.smpRate)))
                                // sample
                                if (seqASDUItem.sample !== undefined) {
                                    seqASDUItemTLVs.push(new TLV(0x87, Buffer.from(seqASDUItem.sample, 'hex')))
                                } else {
                                    this.recordError(`svPdu.seqASDU[${index}]`, 'No sample')
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

    public id: string = 'sv'

    public name: string = 'IEC61850 Sampled Values'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.etherType === 0x88ba
    }
}
