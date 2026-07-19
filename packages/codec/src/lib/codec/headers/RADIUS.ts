import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One RADIUS attribute (AVP): a type and its verbatim hex value (the on-wire length = value bytes + 2). */
type RadiusAttribute = {type: number, value: string}

/**
 * RADIUS — Remote Authentication Dial-In User Service (RFC 2865 auth / RFC 2866 accounting), UDP ports
 * 1812 (auth) and 1813 (accounting). A 20-byte fixed header — Code, Identifier, Length (the whole
 * packet), and a 16-byte Authenticator — followed by attributes (AVPs) in Type-Length-Value form:
 * type(1) + length(1, counts the type+length+value) + value(length-2).
 *
 * Attributes are carried generically (type + verbatim hex value) so every attribute — including
 * Vendor-Specific (26) whose value nests sub-AVPs — round-trips byte-for-byte; per-attribute semantic
 * decoding is a later enrichment. The AVP walk is bounded by the RADIUS Length (and the UDP payload),
 * so any trailing padding/FCS spills to the raw layer.
 */
export class RADIUS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (RADIUS.#schemaCache ??= RADIUS.#buildSchema())
    }

    /** Bytes available for this RADIUS message: the frame end, clamped by the UDP payload and the RADIUS Length. */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        const radiusLength: number = this.instance.length.getValue(0)
        if (radiusLength >= 20 && radiusLength < available) available = radiusLength
        return available < 0 ? 0 : available
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'RADIUS code=${code} id=${identifier}',
            properties: {
                code: this.fieldUInt('code', 0, 1, 'Code'),
                identifier: this.fieldUInt('identifier', 1, 1, 'Identifier'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: RADIUS): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: RADIUS): void {
                        //Honor an explicitly-set Length (even 0 — so a decoded malformed Length=0 still
                        //round-trips byte-for-byte); auto-compute only when the field is absent (crafting).
                        const length: number | undefined = this.instance.length.getValue()
                        if (length !== undefined && length !== null) {
                            this.instance.length.setValue(length)
                            this.writeBytes(2, UInt16ToBuffer(length))
                        } else {
                            this.writeBytes(2, UInt16ToBuffer(0))
                            //After the attributes have encoded, the header length is the whole message.
                            this.addPostSelfEncodeHandler((): void => {
                                this.instance.length.setValue(this.length)
                                this.writeBytes(2, UInt16ToBuffer(this.length))
                            }, 1)
                        }
                    }
                },
                authenticator: this.fieldHex('authenticator', 4, 16, 'Authenticator'),
                attributes: {
                    type: 'array',
                    label: 'Attributes',
                    items: {
                        type: 'object',
                        label: 'Attribute',
                        properties: {
                            type: {type: 'integer', label: 'Type', minimum: 0, maximum: 255},
                            value: {type: 'string', label: 'Value', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: RADIUS): void {
                        const available: number = this.#available()
                        const attributes: RadiusAttribute[] = []
                        let offset: number = 20
                        //Each AVP is type(1) length(1) value(length-2). A length < 2 is invalid (and would
                        //not advance), and a length that overruns the payload is truncated — in both cases
                        //stop and leave the remaining bytes to the raw layer, keeping the round-trip exact.
                        while (offset + 2 <= available) {
                            const type: number = BufferToUInt8(this.readBytes(offset, 1, true))
                            const length: number = BufferToUInt8(this.readBytes(offset + 1, 1, true))
                            if (length < 2 || offset + length > available) break
                            const attributeBuffer: Buffer = this.readBytes(offset, length)
                            attributes.push({type: type, value: length > 2 ? BufferToHex(attributeBuffer.subarray(2)) : ''})
                            offset += length
                        }
                        this.instance.attributes.setValue(attributes)
                    },
                    encode: function (this: RADIUS): void {
                        const attributes: RadiusAttribute[] = this.instance.attributes.getValue([])
                        if (!attributes) return
                        let offset: number = 20
                        for (const attribute of attributes) {
                            const value: Buffer = HexToBuffer(attribute.value ? attribute.value : '')
                            this.writeBytes(offset, UInt8ToBuffer(attribute.type ? attribute.type : 0))
                            this.writeBytes(offset + 1, UInt8ToBuffer(value.length + 2))
                            offset += 2
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

    public readonly id: string = 'radius'

    public readonly name: string = 'Remote Authentication Dial-In User Service'

    public readonly nickname: string = 'RADIUS'

    public readonly matchKeys: string[] = ['udpport:1812', 'udpport:1813']

    public match(): boolean {
        //Require the full 20-byte fixed header within the UDP PAYLOAD (not just the captured frame — a
        //padded sub-20-byte datagram on a RADIUS port would otherwise over-read the trailer into the
        //header). During MATCH the Length field is unset, so #available() reduces to the UDP-payload bound.
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp' && this.#available() >= 20
    }

    //A leaf header — nothing demuxes above RADIUS.
    public readonly demuxProducers: DemuxProducer[] = []

}
