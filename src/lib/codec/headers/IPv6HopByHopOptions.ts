import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {BufferToUInt8} from '../../helper/BufferToNumber'
import {UInt16ToBuffer, UInt32ToBuffer, UInt64ToBuffer, UInt8ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import TLV from 'node-tlv'
import {HexToUInt16, HexToUInt32, HexToUInt64, HexToUInt8} from '../../helper/HexToNumber'

//Type=1 PadN
//Type=4 Tunnel Encapsulation Limit
//Type=5 Router Alert
//Type=7 CALIPSO
//Type=8 SMF_DPD
//Type=11 MPL Option
//Type=12 ILNP Nonce
//Type=13 Line-Identification Option
//Type=30 IPv6 DFF Header
//Type=138 Endpoint Identification

enum Type {
    PadN = 'PadN',
    Tunnel_Encapsulation_Limit = 'Tunnel-Encapsulation-Limit',
    Router_Alert = 'Router-Alert',
    CALIPSO = 'CALIPSO',
    SMF_DPD = 'SMF_DPD',
    MPL_Option = 'MPL-Option',
    ILNP_Nonce = 'ILNP-Nonce',
    Line_Identification_Option = 'Line-Identification-Option',
    IPv6_DFF_Header = 'IPv6-DFF-Header',
    Endpoint_Identification = 'Endpoint-Identification'
}

type PadN = {
    type: Type.PadN
    n: number
}
type Tunnel_Encapsulation_Limit = {
    type: Type.Tunnel_Encapsulation_Limit
    limit: number
}
type Router_Alert = {
    type: Type.Router_Alert
    alert: string
}
type CALIPSO = {
    type: Type.CALIPSO
    tag: string
}
type SMF_DPD = {
    type: Type.SMF_DPD
    hash: string
}
type MPL_Option = {
    type: Type.MPL_Option
    value: string
}
type ILNP_Nonce = {
    type: Type.ILNP_Nonce
    nonce: string
}
type Line_Identification_Option = {
    type: Type.Line_Identification_Option
    id: string
}
type IPv6_DFF_Header = {
    type: Type.IPv6_DFF_Header
    message: string
}
type Endpoint_Identification = {
    type: Type.Endpoint_Identification
    id: string
}
type Custom = {
    type: number
    data: string
}

export class IPv6HopByHopOptions extends BaseHeader {

    protected itemTLVs: TLV[]

    protected items: (
        PadN |
        Tunnel_Encapsulation_Limit |
        Router_Alert |
        CALIPSO |
        SMF_DPD |
        MPL_Option |
        ILNP_Nonce |
        Line_Identification_Option |
        IPv6_DFF_Header |
        Endpoint_Identification |
        Custom
        )[] = []

    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            nxt: {
                type: 'integer',
                label: 'Next Header',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.nxt.setValue(BufferToUInt8(this.readBytes(0, 1)))
                },
                encode: (): void => {
                    const nxt: number = this.instance.nxt.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.nxt.setValue(nxt)
                    this.writeBytes(0, UInt8ToBuffer(nxt))
                }
            },
            len: {
                type: 'integer',
                label: 'Length',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.len.setValue(BufferToUInt8(this.readBytes(1, 1)))
                },
                encode: (): void => {
                    const len: number = this.instance.len.getValue(0)
                    this.instance.len.setValue(len)
                    this.writeBytes(1, UInt8ToBuffer(len))
                    if (!len) {
                        this.addPostSelfEncodeHandler((): void => {
                            let rawLength: number = 0
                            this.itemTLVs
                                .map(tlv => Buffer.from(tlv.getTLV(), 'hex').length)
                                .forEach(itemLength => rawLength += itemLength)
                            const calcLength: number = Math.floor(rawLength / 8)
                            this.instance.len.setValue(calcLength)
                            this.writeBytes(1, UInt8ToBuffer(calcLength))
                        })
                    }
                }
            },
            items: {
                type: 'array',
                label: 'Option Items',
                items: {
                    anyOf: [
                        //Type=1 PadN
                        {
                            type: 'object',
                            label: 'PadN',
                            properties: {
                                type: {
                                    type: 'string',
                                    label: 'Type',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [Type.PadN]
                                },
                                n: {
                                    type: 'integer',
                                    label: 'N'
                                }
                            }
                        },
                        //Type=4 Tunnel Encapsulation Limit
                        {
                            type: 'object',
                            label: 'Tunnel Encapsulation Limit',
                            properties: {
                                type: {
                                    type: 'string',
                                    label: 'Type',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [Type.Tunnel_Encapsulation_Limit]
                                },
                                limit: {
                                    type: 'integer',
                                    label: 'Limit',
                                    minimum: 1,
                                    maximum: 255
                                }
                            }
                        },
                        //Type=5 Router Alert
                        {
                            type: 'object',
                            label: 'Router Alert',
                            properties: {
                                type: {
                                    type: 'string',
                                    label: 'Type',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [Type.Router_Alert]
                                },
                                alert: {
                                    type: 'string',
                                    label: 'Router Alert',
                                    contentEncoding: StringContentEncodingEnum.HEX,
                                    minLength: 4,
                                    maxLength: 4
                                }
                            }
                        },
                        //Type=7 CALIPSO
                        {
                            type: 'object',
                            label: 'CALIPSO',
                            properties: {
                                type: {
                                    type: 'string',
                                    label: 'Type',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [Type.CALIPSO]
                                },
                                tag: {
                                    type: 'string',
                                    label: 'Tag',
                                    contentEncoding: StringContentEncodingEnum.HEX,
                                    minLength: 16,
                                    maxLength: 16
                                }
                            }
                        },
                        //Type=8 SMF_DPD
                        {
                            type: 'object',
                            label: 'SMF_DPD',
                            properties: {
                                type: {
                                    type: 'string',
                                    label: 'Type',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [Type.SMF_DPD]
                                },
                                hash: {
                                    type: 'string',
                                    label: 'Hash',
                                    contentEncoding: StringContentEncodingEnum.UTF8
                                }
                            }
                        },
                        //Type=11 MPL Option
                        {
                            type: 'object',
                            label: 'MPL Option',
                            properties: {
                                type: {
                                    type: 'string',
                                    label: 'Type',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [Type.MPL_Option]
                                },
                                value: {
                                    type: 'string',
                                    label: 'Value',
                                    contentEncoding: StringContentEncodingEnum.HEX
                                }
                            }
                        },
                        //Type=12 ILNP Nonce
                        {
                            type: 'object',
                            label: 'ILNP Nonce',
                            properties: {
                                type: {
                                    type: 'string',
                                    label: 'Type',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [Type.ILNP_Nonce]
                                },
                                nonce: {
                                    type: 'string',
                                    label: 'Nonce',
                                    minLength: 12,
                                    maxLength: 12,
                                    contentEncoding: StringContentEncodingEnum.HEX
                                }
                            }
                        },
                        //Type=13 Line-Identification Option
                        {
                            type: 'object',
                            label: 'Line-Identification Option',
                            properties: {
                                type: {
                                    type: 'string',
                                    label: 'Type',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [Type.Line_Identification_Option]
                                },
                                id: {
                                    type: 'string',
                                    label: 'Identity',
                                    minLength: 8,
                                    maxLength: 8,
                                    contentEncoding: StringContentEncodingEnum.HEX
                                }
                            }
                        },
                        //Type=30 IPv6 DFF Header
                        {
                            type: 'object',
                            label: 'IPv6 DFF Header',
                            properties: {
                                type: {
                                    type: 'string',
                                    label: 'Type',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [Type.IPv6_DFF_Header]
                                },
                                message: {
                                    type: 'string',
                                    label: 'Message',
                                    contentEncoding: StringContentEncodingEnum.HEX
                                }
                            }
                        },
                        //Type=138 Endpoint Identification
                        {
                            type: 'object',
                            label: 'Endpoint Identification',
                            properties: {
                                type: {
                                    type: 'string',
                                    label: 'Type',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [Type.Endpoint_Identification]
                                },
                                id: {
                                    type: 'string',
                                    label: 'Identity',
                                    minLength: 32,
                                    maxLength: 32,
                                    contentEncoding: StringContentEncodingEnum.HEX
                                }
                            }
                        },
                        //Custom
                        {
                            type: 'object',
                            label: 'Custom',
                            properties: {
                                type: {
                                    type: 'integer',
                                    label: 'Type'
                                },
                                data: {
                                    type: 'string',
                                    label: 'Data',
                                    contentEncoding: StringContentEncodingEnum.HEX
                                }
                            }
                        }
                    ]
                },
                decode: (): void => {
                    let length: number = this.instance.len.getValue(0) * 8 + 7
                    while (!this.itemTLVs) {
                        try {
                            const itemTLVs: TLV[] = TLV.parseList(this.readBytes(2, length, true))
                            const joinedHex: string = itemTLVs.map(value => value.getTLV()).join('')
                            if (this.readBytes(2, length, true).toString('hex').padStart(length * 2, '0').toUpperCase() !== joinedHex.toUpperCase()) {
                                length -= 1
                                if (!length) break
                                continue
                            }
                            this.itemTLVs = TLV.parseList(this.readBytes(2, length))
                        } catch (e) {
                            length -= 1
                            if (!length) break
                        }
                    }
                    this.itemTLVs.forEach((itemTLV: TLV): void => {
                        switch (itemTLV.getTag('number')) {
                            case 0x01: {
                                this.items.push({
                                    type: Type.PadN,
                                    n: itemTLV.getLength('number')
                                })
                            }
                                break
                            case 0x04: {
                                this.items.push({
                                    type: Type.Tunnel_Encapsulation_Limit,
                                    limit: HexToUInt8(itemTLV.getValue('hex'))
                                })
                            }
                                break
                            case 0x05: {
                                this.items.push({
                                    type: Type.Router_Alert,
                                    alert: itemTLV.getValue('hex')
                                })
                            }
                                break
                            case 0x07: {
                                this.items.push({
                                    type: Type.CALIPSO,
                                    tag: itemTLV.getValue('hex')
                                })
                            }
                                break
                            case 0x08: {
                                this.items.push({
                                    type: Type.SMF_DPD,
                                    hash: itemTLV.getValue('hex')
                                })
                            }
                                break
                            case 0x0B: {
                                this.items.push({
                                    type: Type.MPL_Option,
                                    value: itemTLV.getValue('hex')
                                })
                            }
                                break
                            case 0x0C: {
                                this.items.push({
                                    type: Type.ILNP_Nonce,
                                    nonce: itemTLV.getValue('hex')
                                })
                            }
                                break
                            case 0x0D: {
                                this.items.push({
                                    type: Type.Line_Identification_Option,
                                    id: itemTLV.getValue('hex')
                                })
                            }
                                break
                            case 0x1E: {
                                this.items.push({
                                    type: Type.IPv6_DFF_Header,
                                    message: itemTLV.getValue('hex')
                                })
                            }
                                break
                            case 0x8A: {
                                this.items.push({
                                    type: Type.Endpoint_Identification,
                                    id: itemTLV.getValue('hex')
                                })
                            }
                                break
                            default: {
                                this.items.push({
                                    type: itemTLV.getTag('number'),
                                    data: itemTLV.getValue('hex')
                                })
                            }
                        }
                    })
                    this.instance.items.setValue(this.items.length ? this.items : [])
                },
                encode: (): void => {
                    this.items = this.instance.items.getValue([])
                    this.itemTLVs = []
                    this.items.forEach(item => {
                        switch (item.type) {
                            case Type.PadN: {
                                const typedItem: PadN = {...item}
                                this.itemTLVs.push(new TLV(0x01, Buffer.alloc(typedItem.n, 0)))
                            }
                                break
                            case Type.Tunnel_Encapsulation_Limit: {
                                const typedItem: Tunnel_Encapsulation_Limit = {...item}
                                this.itemTLVs.push(new TLV(0x04, UInt8ToBuffer(typedItem.limit)))
                            }
                                break
                            case Type.Router_Alert: {
                                const typedItem: Router_Alert = {...item}
                                this.itemTLVs.push(new TLV(0x05, UInt16ToBuffer(HexToUInt16(typedItem.alert))))
                            }
                                break
                            case Type.CALIPSO: {
                                const typedItem: CALIPSO = {...item}
                                this.itemTLVs.push(new TLV(0x07, UInt64ToBuffer(HexToUInt64(typedItem.tag))))
                            }
                                break
                            case Type.SMF_DPD: {
                                const typedItem: SMF_DPD = {...item}
                                this.itemTLVs.push(new TLV(0x08, Buffer.from(typedItem.hash, 'hex')))
                            }
                                break
                            case Type.MPL_Option: {
                                const typedItem: MPL_Option = {...item}
                                this.itemTLVs.push(new TLV(0x0B, Buffer.from(typedItem.value, 'hex')))
                            }
                                break
                            case Type.ILNP_Nonce: {
                                const typedItem: ILNP_Nonce = {...item}
                                this.itemTLVs.push(new TLV(0x0C, Buffer.from(typedItem.nonce.padStart(12, '0'), 'hex')))
                            }
                                break
                            case Type.Line_Identification_Option: {
                                const typedItem: Line_Identification_Option = {...item}
                                this.itemTLVs.push(new TLV(0x0D, UInt32ToBuffer(HexToUInt32(typedItem.id))))
                            }
                                break
                            case Type.IPv6_DFF_Header: {
                                const typedItem: IPv6_DFF_Header = {...item}
                                this.itemTLVs.push(new TLV(0x1E, Buffer.from(typedItem.message, 'hex')))
                            }
                                break
                            case Type.Endpoint_Identification: {
                                const typedItem: Endpoint_Identification = {...item}
                                this.itemTLVs.push(new TLV(0x0C, Buffer.from(typedItem.id.padStart(32, '0'), 'hex')))
                            }
                                break
                            default: {
                                if (typeof item.type !== 'number') return
                                const customItem: Custom = {...item}
                                this.itemTLVs.push(new TLV(customItem.type, Buffer.from(customItem.data, 'hex')))
                            }
                        }
                    })
                    const itemsBuffer: Buffer = Buffer.from(this.itemTLVs.map(value => value.getTLV()).join(''), 'hex')
                    this.writeBytes(2, itemsBuffer)
                }
            }
        }
    }

    public id: string = 'ipv6-hopopt'

    public name: string = 'IPv6 Hop-by-Hop Option'

    public nickname: string = 'HopOpt'

    public readonly isProtocol: boolean = false

    public match(): boolean {
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'ipv6') return false
        return this.prevCodecModule.instance.nxt.getValue() === 0x00
    }

}
