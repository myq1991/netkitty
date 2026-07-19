import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * One STUN attribute: a TLV kept byte-verbatim. `type` + hex `value` (the wire Length is derived from
 * the value byte length). `pad` carries the actual padding bytes ONLY when they are non-zero — RFC 5389
 * §15 permits padding to be any value, so preserving it keeps the frame byte-perfect; the common
 * zero-padding case omits the field entirely and re-emits zeros.
 */
type StunAttribute = {
    type: number
    value: string
    pad?: string
}

/**
 * STUN — Session Traversal Utilities for NAT (RFC 5389, superseded by RFC 8489 with the same wire
 * format). A 20-byte fixed header — Message Type, Message Length, the 0x2112A442 Magic Cookie and a
 * 96-bit Transaction ID (RFC 5389 §6) — followed by zero or more Type-Length-Value attributes
 * (§15), each padded to a 4-byte boundary. Rides UDP/TCP, well-known port 3478.
 *
 * Attributes are carried generically (attribute type + verbatim hex value) so every attribute —
 * standard or unknown — round-trips byte-for-byte; per-attribute semantic decoding (XOR-MAPPED-ADDRESS
 * → ip:port, etc.) is a later enrichment layered on top of this faithful TLV base. Padding bytes are
 * re-emitted as zero (RFC 5389 §15: padding bits are ignored and MAY be any value).
 */
export class STUN extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (STUN.#schemaCache ??= STUN.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            properties: {
                //Message Type (RFC 5389 §6): 14 bits of class+method, top 2 bits zero. Kept as a plain
                //uint16 (e.g. 0x0001 Binding Request, 0x0101 Binding Success Response) — byte-perfect and
                //editable; the class/method split is UI enrichment for later.
                messageType: this.fieldUInt('messageType', 0, 2, 'Message Type'),
                //Message Length: attribute bytes only (excludes the 20-byte header), including padding.
                //Explicit non-zero is honored (a crafted wrong length is a valid packet); 0 auto-computes
                //from the encoded attributes after they are written.
                messageLength: {
                    type: 'integer',
                    label: 'Message Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: STUN): void {
                        this.instance.messageLength.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: STUN): void {
                        const messageLength: number = this.instance.messageLength.getValue(0)
                        if (messageLength) {
                            this.instance.messageLength.setValue(messageLength)
                            this.writeBytes(2, UInt16ToBuffer(messageLength))
                        } else {
                            this.writeBytes(2, UInt16ToBuffer(0))
                            this.instance.messageLength.setValue(0)
                            //After every field (attributes included) has encoded, the header length is
                            //20 + attribute bytes; fill in the real Message Length.
                            this.addPostSelfEncodeHandler((): void => {
                                const attributeBytes: number = this.length - 20 < 0 ? 0 : this.length - 20
                                this.instance.messageLength.setValue(attributeBytes)
                                this.writeBytes(2, UInt16ToBuffer(attributeBytes))
                            }, 1)
                        }
                    }
                },
                magicCookie: this.fieldHex('magicCookie', 4, 4, 'Magic Cookie'),
                transactionId: this.fieldHex('transactionId', 8, 12, 'Transaction ID'),
                attributes: {
                    type: 'array',
                    label: 'Attributes',
                    items: {
                        type: 'object',
                        label: 'Attribute',
                        properties: {
                            type: {
                                type: 'integer',
                                label: 'Attribute Type',
                                minimum: 0,
                                maximum: 65535
                            },
                            value: {
                                type: 'string',
                                label: 'Value',
                                contentEncoding: StringContentEncodingEnum.HEX
                            },
                            //Present only when the on-wire padding is non-zero (RFC 5389 §15 lets it be
                            //any value); hidden from the default form since padding is not semantic.
                            pad: {
                                type: 'string',
                                label: 'Padding',
                                contentEncoding: StringContentEncodingEnum.HEX,
                                hidden: true
                            }
                        }
                    },
                    decode: function (this: STUN): void {
                        const messageLength: number = this.instance.messageLength.getValue(0)
                        //Bound by BOTH the declared Message Length AND the bytes actually present, so a
                        //lying Message Length (e.g. 0xFFFF) cannot spawn phantom attributes past the end
                        //of the buffer. readBytes clamps at the buffer end and offset always advances by
                        //at least 4, so the loop also cannot read out of bounds or run forever.
                        const available: number = this.packet.length - this.startPos
                        const end: number = Math.min(20 + messageLength, available < 20 ? 20 : available)
                        const attributes: StunAttribute[] = []
                        let offset: number = 20
                        //Each attribute is Type(2) Length(2) Value(Length) then padding to a 4-byte boundary.
                        while (offset + 4 <= end) {
                            const type: number = BufferToUInt16(this.readBytes(offset, 2))
                            const length: number = BufferToUInt16(this.readBytes(offset + 2, 2))
                            offset += 4
                            let value: Buffer = Buffer.alloc(0)
                            if (length) {
                                value = this.readBytes(offset, length)
                                offset += length
                            }
                            const padLength: number = (4 - length % 4) % 4
                            const attribute: StunAttribute = {type: type, value: BufferToHex(value)}
                            //Consume the padding so the header length covers it (endPos is exact). Keep
                            //the actual bytes only when non-zero, so a byte round-trip is exact for the
                            //rare legal non-zero padding without polluting the common zero-padded case.
                            if (padLength) {
                                const padding: Buffer = this.readBytes(offset, padLength)
                                offset += padLength
                                if (padding.some((byte: number): boolean => byte !== 0)) attribute.pad = BufferToHex(padding)
                            }
                            attributes.push(attribute)
                        }
                        this.instance.attributes.setValue(attributes)
                    },
                    encode: function (this: STUN): void {
                        const attributes: StunAttribute[] | undefined = this.instance.attributes.getValue()
                        if (!attributes) return
                        let offset: number = 20
                        attributes.forEach((attribute: StunAttribute): void => {
                            const type: number = attribute.type ? attribute.type : 0
                            const value: Buffer = Buffer.from(attribute.value ? attribute.value : '', 'hex')
                            const length: number = value.length
                            this.writeBytes(offset, UInt16ToBuffer(type))
                            this.writeBytes(offset + 2, UInt16ToBuffer(length))
                            offset += 4
                            if (length) {
                                this.writeBytes(offset, value)
                                offset += length
                            }
                            const padLength: number = (4 - length % 4) % 4
                            if (padLength) {
                                //Re-emit preserved non-zero padding verbatim (sized to padLength: extra
                                //dropped, short zero-filled); default zeros when none was carried.
                                const padding: Buffer = Buffer.alloc(padLength, 0)
                                if (attribute.pad) Buffer.from(attribute.pad, 'hex').copy(padding, 0, 0, padLength)
                                this.writeBytes(offset, padding)
                                offset += padLength
                            }
                        })
                    }
                }
            }
        }
    }

    public readonly id: string = 'stun'

    public readonly name: string = 'Session Traversal Utilities for NAT'

    public readonly nickname: string = 'STUN'

    //Well-known port 3478 (UDP and TCP). heuristicFallback because the 0x2112A442 Magic Cookie is a
    //reliable 32-bit content signature — STUN is used on ephemeral ports too (ICE/WebRTC), so it must
    //also be recognized off 3478 via match().
    public readonly matchKeys: string[] = ['udpport:3478', 'tcpport:3478']

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        if (!this.prevCodecModule) return false
        //Magic Cookie 0x2112A442 at offset 4 (RFC 5389 §6). A 32-bit signature — safe to match on any
        //port. RFC 3489 classic STUN (no cookie) is intentionally not matched.
        if (this.packet.length - this.startPos < 8) return false
        return BufferToHex(this.readBytes(4, 4)) === '2112a442'
    }

    //Produces no child demux key — STUN attributes are handled internally; nothing rides above it.
    public readonly demuxProducers: DemuxProducer[] = []

}
