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
    Pad1 = 'Pad1',
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

type Pad1 = {
    type: Type.Pad1
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

    //Byte length of the encoded options area after 8-octet alignment padding.
    //Set during items encode, consumed by the len recompute handler.
    protected paddedOptionsLength: number = 0

    /**
     * Map a decoded Hop-by-Hop option (type + length + hex value) to its structured item.
     * Unknown types become a Custom item so they still round-trip.
     */
    protected decodeHbhOption(type: number, length: number, valueHex: string): IPv6HopByHopOptions['items'][number] {
        switch (type) {
            case 0x01: return {type: Type.PadN, n: length}
            case 0x04: return {type: Type.Tunnel_Encapsulation_Limit, limit: HexToUInt8(valueHex)}
            case 0x05: return {type: Type.Router_Alert, alert: valueHex}
            case 0x07: return {type: Type.CALIPSO, tag: valueHex}
            case 0x08: return {type: Type.SMF_DPD, hash: valueHex}
            case 0x0B: return {type: Type.MPL_Option, value: valueHex}
            case 0x0C: return {type: Type.ILNP_Nonce, nonce: valueHex}
            case 0x0D: return {type: Type.Line_Identification_Option, id: valueHex}
            case 0x1E: return {type: Type.IPv6_DFF_Header, message: valueHex}
            case 0x8A: return {type: Type.Endpoint_Identification, id: valueHex}
            default: return {type: type, data: valueHex}
        }
    }

    protected items: (
        Pad1 |
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
                            //Total header = 2 (nxt+len) + options area, and must be an integral
                            //multiple of 8 octets (RFC 8200 §4.3). items encode already padded the
                            //options area to alignment, so (2 + paddedOptionsLength) is a multiple
                            //of 8 and HdrExtLen = totalOctets/8 - 1.
                            const totalOctets: number = 2 + this.paddedOptionsLength
                            const calcLength: number = Math.max(0, Math.ceil(totalOctets / 8) - 1)
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
                        //Type=0 Pad1 (single octet, no length/value)
                        {
                            type: 'object',
                            label: 'Pad1',
                            properties: {
                                type: {
                                    type: 'string',
                                    label: 'Type',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [Type.Pad1],
                                    const: Type.Pad1,
                                    hidden: true
                                }
                            }
                        },
                        //Type=1 PadN
                        {
                            type: 'object',
                            label: 'PadN',
                            properties: {
                                type: {
                                    type: 'string',
                                    label: 'Type',
                                    contentEncoding: StringContentEncodingEnum.UTF8,
                                    enum: [Type.PadN],
                                    const: Type.PadN,
                                    hidden: true
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
                                    enum: [Type.Tunnel_Encapsulation_Limit],
                                    const: Type.Tunnel_Encapsulation_Limit,
                                    hidden: true
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
                                    enum: [Type.Router_Alert],
                                    const: Type.Router_Alert,
                                    hidden: true
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
                                    enum: [Type.CALIPSO],
                                    const: Type.CALIPSO,
                                    hidden: true
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
                                    enum: [Type.SMF_DPD],
                                    const: Type.SMF_DPD,
                                    hidden: true
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
                                    enum: [Type.MPL_Option],
                                    const: Type.MPL_Option,
                                    hidden: true
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
                                    enum: [Type.ILNP_Nonce],
                                    const: Type.ILNP_Nonce,
                                    hidden: true
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
                                    enum: [Type.Line_Identification_Option],
                                    const: Type.Line_Identification_Option,
                                    hidden: true
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
                                    enum: [Type.IPv6_DFF_Header],
                                    const: Type.IPv6_DFF_Header,
                                    hidden: true
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
                                    enum: [Type.Endpoint_Identification],
                                    const: Type.Endpoint_Identification,
                                    hidden: true
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
                    //Options area length = (HdrExtLen+1)*8 - 2 = len*8 + 6 octets, bounded to the
                    //bytes actually present.
                    const optionsLength: number = this.instance.len.getValue(0) * 8 + 6
                    const buffer: Buffer = this.readBytes(2, optionsLength)
                    this.items = []
                    //Walk the options manually (RFC 8200 §4.2): Pad1 (type 0) is a single octet with
                    //no Length/Value; every other option is type(1)+length(1)+value(length). Bounds
                    //are checked so a truncated area records what it can rather than throwing (and so
                    //an interior Pad1 no longer desyncs a length-prefix TLV parser).
                    let p: number = 0
                    while (p < buffer.length) {
                        const type: number = buffer[p]
                        if (type === 0x00) {
                            this.items.push({type: Type.Pad1})
                            p += 1
                            continue
                        }
                        if (p + 2 > buffer.length) break
                        const optionLength: number = buffer[p + 1]
                        if (p + 2 + optionLength > buffer.length) break
                        const valueHex: string = buffer.subarray(p + 2, p + 2 + optionLength).toString('hex')
                        this.items.push(this.decodeHbhOption(type, optionLength, valueHex))
                        p += 2 + optionLength
                    }
                    this.instance.items.setValue(this.items)
                },
                encode: (): void => {
                    this.items = this.instance.items.getValue([])
                    const parts: Buffer[] = []
                    const tlvBytes: (tlv: TLV) => Buffer = (tlv: TLV): Buffer => Buffer.from(tlv.getTLV(), 'hex')
                    this.items.forEach(item => {
                        switch (item.type) {
                            case Type.Pad1: {
                                //Pad1 is a single zero octet with no Length/Value.
                                parts.push(Buffer.from([0x00]))
                            }
                                break
                            case Type.PadN: {
                                const typedItem: PadN = {...item}
                                parts.push(tlvBytes(new TLV(0x01, Buffer.alloc(typedItem.n, 0))))
                            }
                                break
                            case Type.Tunnel_Encapsulation_Limit: {
                                const typedItem: Tunnel_Encapsulation_Limit = {...item}
                                parts.push(tlvBytes(new TLV(0x04, UInt8ToBuffer(typedItem.limit))))
                            }
                                break
                            case Type.Router_Alert: {
                                const typedItem: Router_Alert = {...item}
                                parts.push(tlvBytes(new TLV(0x05, UInt16ToBuffer(HexToUInt16(typedItem.alert)))))
                            }
                                break
                            case Type.CALIPSO: {
                                const typedItem: CALIPSO = {...item}
                                parts.push(tlvBytes(new TLV(0x07, UInt64ToBuffer(HexToUInt64(typedItem.tag)))))
                            }
                                break
                            case Type.SMF_DPD: {
                                const typedItem: SMF_DPD = {...item}
                                parts.push(tlvBytes(new TLV(0x08, Buffer.from(typedItem.hash, 'hex'))))
                            }
                                break
                            case Type.MPL_Option: {
                                const typedItem: MPL_Option = {...item}
                                parts.push(tlvBytes(new TLV(0x0B, Buffer.from(typedItem.value, 'hex'))))
                            }
                                break
                            case Type.ILNP_Nonce: {
                                const typedItem: ILNP_Nonce = {...item}
                                parts.push(tlvBytes(new TLV(0x0C, Buffer.from(typedItem.nonce.padStart(12, '0'), 'hex'))))
                            }
                                break
                            case Type.Line_Identification_Option: {
                                const typedItem: Line_Identification_Option = {...item}
                                parts.push(tlvBytes(new TLV(0x0D, UInt32ToBuffer(HexToUInt32(typedItem.id)))))
                            }
                                break
                            case Type.IPv6_DFF_Header: {
                                const typedItem: IPv6_DFF_Header = {...item}
                                parts.push(tlvBytes(new TLV(0x1E, Buffer.from(typedItem.message, 'hex'))))
                            }
                                break
                            case Type.Endpoint_Identification: {
                                const typedItem: Endpoint_Identification = {...item}
                                parts.push(tlvBytes(new TLV(0x8A, Buffer.from(typedItem.id.padStart(32, '0'), 'hex'))))
                            }
                                break
                            default: {
                                if (typeof item.type !== 'number') return
                                const customItem: Custom = {...item}
                                parts.push(tlvBytes(new TLV(customItem.type, Buffer.from(customItem.data, 'hex'))))
                            }
                        }
                    })
                    let itemsBuffer: Buffer = Buffer.concat(parts)
                    //Pad the options area so the whole header (2 header bytes + options) is an
                    //integral multiple of 8 octets (RFC 8200 §4.3). Use a PadN option (type 0x01)
                    //for >=2 bytes so it re-decodes as a PadN, and a single Pad1 (0x00) for 1 byte.
                    const pad: number = (8 - (2 + itemsBuffer.length) % 8) % 8
                    if (pad === 1) {
                        itemsBuffer = Buffer.concat([itemsBuffer, Buffer.from([0x00])])
                    } else if (pad >= 2) {
                        const padN: TLV = new TLV(0x01, Buffer.alloc(pad - 2, 0))
                        itemsBuffer = Buffer.concat([itemsBuffer, Buffer.from(padN.getTLV(), 'hex')])
                    }
                    this.paddedOptionsLength = itemsBuffer.length
                    this.writeBytes(2, itemsBuffer)
                }
            }
        }
    }

    public id: string = 'ipv6-hopopt'

    public readonly matchKeys: string[] = ['ipproto:0']

    public name: string = 'IPv6 Hop-by-Hop Option'

    public nickname: string = 'HopOpt'

    public readonly isProtocol: boolean = false

    public match(): boolean {
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'ipv6') return false
        return this.prevCodecModule.instance.nxt.getValue() === 0x00
    }

}
