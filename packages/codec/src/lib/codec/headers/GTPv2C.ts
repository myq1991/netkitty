import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One GTPv2-C Information Element: Type + (preserved) spare nibble + Instance nibble + verbatim hex Value. */
type Gtpv2Ie = {type: number, spare: number, instance: number, value: string}

/**
 * GTPv2-C — GPRS Tunnelling Protocol version 2, Control plane (3GPP TS 29.274), UDP port 2123. The
 * mandatory part is the first 4 octets: a Flags byte (Version[3] = 2, P = Piggybacking, T = TEID flag,
 * then 3 spare bits), a Message Type (1 Echo Request, 2 Echo Response, 32 Create Session Request,
 * 33 Create Session Response, …), and a 2-byte Message Length (the octet count of everything after
 * these first 4 octets). When the T flag is set a 4-byte TEID follows; then a 3-byte Sequence Number
 * and a 1-byte Spare are always present. The rest of the message is a flat list of Information Elements,
 * each a 1-byte Type, a 2-byte Length (the value byte count), a byte carrying a 4-bit spare + 4-bit
 * Instance, and Length value octets.
 *
 * IEs are carried generically (type + instance + verbatim hex value) so every IE — including grouped and
 * vendor-specific ones whose value is opaque — round-trips byte-for-byte; per-IE semantic decoding is a
 * later enrichment. The Message Length is honoured verbatim when supplied (a crafted message may lie),
 * else derived from the actual TEID/Sequence/Spare/IE bytes. The IE walk is bounded by both the Message
 * Length and the UDP datagram, so retained Ethernet padding / trailing bytes are not absorbed. A
 * well-formed message round-trips byte-for-byte. GTPv2-C is a leaf — nothing rides on top of it.
 */
export class GTPv2C extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (GTPv2C.#schemaCache ??= GTPv2C.#buildSchema())
    }

    /** A single flag bit of the first byte (byte 0), MSB-first: bitOffset 3 = P, 4 = T. */
    static #flagBit(name: string, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'boolean',
            label: label,
            decode: function (this: GTPv2C): void {
                (this.instance.flags as any)[name].setValue(!!this.readBits(0, 1, bitOffset, 1))
            },
            encode: function (this: GTPv2C): void {
                const value: boolean = !!(this.instance.flags as any)[name].getValue()
                ;(this.instance.flags as any)[name].setValue(value)
                this.writeBits(0, 1, bitOffset, 1, value ? 1 : 0)
            }
        }
    }

    /** True when the T (TEID) flag is set — a 4-byte TEID then sits between the length field and the sequence number. */
    #teidPresent(): boolean {
        return !!this.instance.flags.teidFlag.getValue()
    }

    /** Header-relative offset of the 3-byte Sequence Number: after the 4 mandatory octets, +4 for the TEID when present. */
    #sequenceOffset(): number {
        return this.#teidPresent() ? 8 : 4
    }

    /** The payload length available to this message, clamped by the UDP datagram (so padding/FCS is not absorbed). */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /** Header-relative end offset of the IE list: 4 (mandatory) + Message Length, clamped down to the UDP payload. */
    #messageEnd(): number {
        let end: number = 4 + this.instance.messageLength.getValue(0)
        const available: number = this.#available()
        if (available && available < end) end = available
        return end
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'GTPv2-C type=${messageType} seq=${sequenceNumber}',
            properties: {
                //Byte 0 (MSB-first): Version[0..2] (= 2), P[3] Piggybacking, T[4] TEID flag, spare[5..7].
                flags: {
                    type: 'object',
                    label: 'Flags',
                    properties: {
                        version: {
                            type: 'integer',
                            label: 'Version',
                            minimum: 0,
                            maximum: 7,
                            decode: function (this: GTPv2C): void { this.instance.flags.version.setValue(this.readBits(0, 1, 0, 3)) },
                            encode: function (this: GTPv2C): void { this.writeBits(0, 1, 0, 3, this.instance.flags.version.getValue(2)) }
                        },
                        piggybacking: this.#flagBit('piggybacking', 3, 'Piggybacking'),
                        teidFlag: this.#flagBit('teidFlag', 4, 'TEID Flag'),
                        //3 spare bits kept verbatim so a non-canonical first byte still round-trips.
                        spare: {
                            type: 'integer',
                            label: 'Spare',
                            minimum: 0,
                            maximum: 7,
                            hidden: true,
                            decode: function (this: GTPv2C): void { this.instance.flags.spare.setValue(this.readBits(0, 1, 5, 3)) },
                            encode: function (this: GTPv2C): void { this.writeBits(0, 1, 5, 3, this.instance.flags.spare.getValue(0)) }
                        }
                    }
                },
                messageType: this.fieldUInt('messageType', 1, 1, 'Message Type'),
                messageLength: {
                    type: 'integer',
                    label: 'Message Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: GTPv2C): void {
                        this.instance.messageLength.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: GTPv2C): void {
                        //Message Length counts every octet after the first 4: the TEID (if T), the 3-byte
                        //Sequence Number, the 1-byte Spare, and all IEs. Honoured when supplied (a crafted
                        //message may lie); else derived from the actual fields.
                        const provided: number | undefined = this.instance.messageLength.getValue()
                        let value: number
                        if (provided !== undefined && provided !== null) {
                            value = provided
                        } else {
                            let iesBytes: number = 0
                            const ies: Gtpv2Ie[] = this.instance.ies.getValue([])
                            if (ies) for (const ie of ies) iesBytes += 4 + HexToBuffer(ie.value ? ie.value : '').length
                            value = (this.#teidPresent() ? 4 : 0) + 3 + 1 + iesBytes
                        }
                        if (value > 65535) {
                            this.recordError(this.instance.messageLength.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        this.instance.messageLength.setValue(value)
                        this.writeBytes(2, UInt16ToBuffer(value))
                    }
                },
                //4-byte TEID, present only when the T flag is set. Kept verbatim as hex.
                teid: {
                    type: 'string',
                    label: 'TEID',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: GTPv2C): void {
                        if (!this.#teidPresent()) return
                        this.instance.teid.setValue(BufferToHex(this.readBytes(4, 4)))
                    },
                    encode: function (this: GTPv2C): void {
                        if (!this.#teidPresent()) return
                        this.writeBytes(4, HexToBuffer(this.instance.teid.getValue('00000000')))
                    }
                },
                //3-byte Sequence Number, at offset 4 (no TEID) or 8 (TEID present).
                sequenceNumber: {
                    type: 'integer',
                    label: 'Sequence Number',
                    minimum: 0,
                    maximum: 16777215,
                    decode: function (this: GTPv2C): void {
                        this.instance.sequenceNumber.setValue(this.readBits(this.#sequenceOffset(), 3, 0, 24))
                    },
                    encode: function (this: GTPv2C): void {
                        const node: any = this.instance.sequenceNumber
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 16777215) {
                            this.recordError(node.getPath(), 'Maximum value is 16777215')
                            value = 16777215
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBits(this.#sequenceOffset(), 3, 0, 24, value)
                    }
                },
                //1-byte Spare after the Sequence Number, kept verbatim.
                spare: {
                    type: 'string',
                    label: 'Spare',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    hidden: true,
                    decode: function (this: GTPv2C): void {
                        this.instance.spare.setValue(BufferToHex(this.readBytes(this.#sequenceOffset() + 3, 1)))
                    },
                    encode: function (this: GTPv2C): void {
                        this.writeBytes(this.#sequenceOffset() + 3, HexToBuffer(this.instance.spare.getValue('00')))
                    }
                },
                //Information Elements: a flat list from the end of the mandatory part to the Message Length
                //end (clamped to the UDP payload). Each IE = Type(1) + Length(2) + (spare[4]+Instance[4])(1)
                //+ Length value octets. The Length is derived from the value byte count on encode.
                ies: {
                    type: 'array',
                    label: 'Information Elements',
                    items: {
                        type: 'object',
                        label: 'IE',
                        properties: {
                            type: {type: 'integer', label: 'Type', minimum: 0, maximum: 255},
                            spare: {type: 'integer', label: 'Spare', minimum: 0, maximum: 15, hidden: true},
                            instance: {type: 'integer', label: 'Instance', minimum: 0, maximum: 15},
                            value: {type: 'string', label: 'Value', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: GTPv2C): void {
                        const end: number = this.#messageEnd()
                        const ies: Gtpv2Ie[] = []
                        let offset: number = this.#sequenceOffset() + 4
                        //Each IE needs a 4-byte header; stop when it or its value would overrun the bound.
                        while (offset + 4 <= end) {
                            const type: number = BufferToUInt8(this.readBytes(offset, 1))
                            const length: number = BufferToUInt16(this.readBytes(offset + 1, 2))
                            const instByte: number = BufferToUInt8(this.readBytes(offset + 3, 1))
                            const valueStart: number = offset + 4
                            if (valueStart + length > end) break
                            const value: string = length > 0 ? BufferToHex(this.readBytes(valueStart, length)) : ''
                            ies.push({type: type, spare: instByte >> 4, instance: instByte & 0x0f, value: value})
                            offset = valueStart + length
                        }
                        this.instance.ies.setValue(ies)
                    },
                    encode: function (this: GTPv2C): void {
                        const ies: Gtpv2Ie[] = this.instance.ies.getValue([])
                        if (!ies) return
                        let offset: number = this.#sequenceOffset() + 4
                        for (let i: number = 0; i < ies.length; i++) {
                            const ie: Gtpv2Ie = ies[i]
                            let value: Buffer = HexToBuffer(ie.value ? ie.value : '')
                            //The IE Length is a 16-bit field; a longer value cannot be represented, so clamp
                            //it and record the error rather than silently wrapping (which corrupts the chain).
                            if (value.length > 65535) {
                                this.recordError(`ies[${i}].value`, 'Maximum IE value length is 65535 bytes')
                                value = value.subarray(0, 65535)
                            }
                            this.writeBytes(offset, UInt8ToBuffer(ie.type ? ie.type : 0))
                            this.writeBytes(offset + 1, UInt16ToBuffer(value.length))
                            const spare: number = ie.spare ? ie.spare : 0
                            const instance: number = ie.instance ? ie.instance : 0
                            this.writeBytes(offset + 3, UInt8ToBuffer(((spare & 0x0f) << 4) | (instance & 0x0f)))
                            offset += 4
                            if (value.length) {
                                this.writeBytes(offset, value)
                                offset += value.length
                            }
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'gtpv2'

    public readonly name: string = 'GPRS Tunnelling Protocol version 2, Control plane'

    public readonly nickname: string = 'GTPv2-C'

    public readonly matchKeys: string[] = ['udpport:2123']

    public match(): boolean {
        //GTPv2-C rides on UDP port 2123 (either endpoint — a request's destination or a response's
        //source). Require the mandatory 8-byte header (flags + type + length + seq + spare, no TEID) to
        //be present in the UDP payload, and Version == 2 in the first byte so GTPv1-C (version 1) on the
        //same port falls through.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        const dstport: number = this.prevCodecModule.instance.dstport.getValue(0)
        const srcport: number = this.prevCodecModule.instance.srcport.getValue(0)
        if (dstport !== 2123 && srcport !== 2123) return false
        if (this.#available() < 8) return false
        return this.readBits(0, 1, 0, 3) === 2
    }

    //A leaf header — the IE values are kept as verbatim hex, so nothing demuxes above GTPv2-C.
    public readonly demuxProducers: DemuxProducer[] = []

}
