import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {CodecModule} from '../types/CodecModule'
import TLV from 'node-tlv'
import {HexToUInt16, HexToUInt32, HexToUInt8} from '../lib/HexToNumber'

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
                decode: (): void => {
                    this.instance.reserved1 = {}
                },
                properties: {
                    simulated: {
                        type: 'boolean',
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
                decode: (): void => {
                    this.instance.reserved2 = {}
                },
                properties: {
                    reserved: {
                        type: 'number',
                        minimum: 0,
                        maximum: 65535,
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
                decode: (): void => {
                    const buffer: Buffer = this.readBytes(8, (this.instance.length as number) - 8)
                    this.TLVInstance = TLV.parse(buffer)
                    this.TLVChild = this.TLVInstance.getChild()
                    this.instance.svPdu = {}
                },
                encode: (): void => {
                    //TODO
                },
                properties: {
                    noASDU: {
                        type: 'integer',
                        minimum: 1,
                        maximum: 65535,
                        decode: (): void => {
                            const noASDUTLV: TLV | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x80)
                            if (!noASDUTLV) return this.recordError('svPdu.noASDU', 'Not Found')
                            const noASDUNum: number = HexToUInt16(noASDUTLV.getValue('hex'))
                            if (!noASDUNum) this.recordError('svPdu.noASDU', 'Number of ASDU should be greater or equal to 1')
                            this.instance.svPdu['noASDU'] = noASDUNum
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    seqASDU: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                svID: {
                                    type: 'string'
                                },
                                dataSet: {
                                    type: 'string'
                                },
                                smpCnt: {
                                    type: 'integer'
                                },
                                confRev: {
                                    type: 'integer'
                                },
                                refrTm: {
                                    type: 'string'
                                },
                                smpSynch: {
                                    type: 'integer'
                                },
                                smpRate: {
                                    type: 'integer'
                                },
                                sample: {
                                    type: 'string'
                                },
                                smpMod: {
                                    type: 'integer'
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
                            //TODO
                        }
                    }
                }
            }
        }
    }

    public id: string = 'sv'

    public name: string = 'IEC61850 Sampled Values'

    public match(prevCodecModule: CodecModule, prevCodecModules: CodecModule[]): boolean {
        if (!prevCodecModule) return false
        return prevCodecModule.instance.etherType === 0x88ba
    }
}
