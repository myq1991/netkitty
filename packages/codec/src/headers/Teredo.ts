import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16} from '../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer} from '../helper/NumberToBuffer'
import {BufferToIPv4} from '../helper/BufferToIP'
import {IPv4ToBuffer} from '../helper/IPToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Teredo — tunneling IPv6 over UDP through NATs (RFC 4380), UDP port 3544. A Teredo message carried in
 * the UDP payload is an inner IPv6 packet, OPTIONALLY prefixed by one or both Teredo indication headers
 * (RFC 4380 §5.1.1), always in this order:
 *
 *   1. Authentication indication (Indicator Type 0x0001): a 2-byte type, a 1-byte Client-ID length, a
 *      1-byte Authentication-value length, the client identifier, the authentication value, an 8-byte
 *      nonce and a 1-byte confirmation. Total = 13 + ID-len + AU-len bytes.
 *   2. Origin indication (Indicator Type 0x0000): a 2-byte type, the 2-byte mapped port and the 4-byte
 *      mapped IPv4 address of the sender as seen by the Teredo relay/server. Total = 8 bytes. Both the
 *      port and the address are OBFUSCATED on the wire by an exclusive-or (RFC 4380 §5.1.1): the port
 *      with 0xFFFF and the address with 0xFFFFFFFF. This codec stores the de-obfuscated (mapped) values
 *      for the editor and re-applies the exclusive-or on encode — XOR is exactly reversible, so the
 *      frame round-trips byte-for-byte.
 *
 * An indication header is detected purely by content: an inner IPv6 packet always begins with the
 * version nibble 6 (first octet 0x6X), so the first two octets can never be 0x0000 or 0x0001 — the two
 * indicator types are therefore unambiguous signatures at the start of the (post-authentication) payload.
 *
 * Minimal slice: the indication headers are parsed into structured fields; the inner IPv6 packet (and
 * anything after the indications) is kept verbatim as `payload` hex and is NOT recursed into — routing
 * it back through the IPv6 header would require changing IPv6.match to accept a Teredo parent, left to a
 * later serial step. The ID-len / AU-len bytes are derived from the client-identifier / authentication-
 * value byte lengths (kept consistent with the bytes actually written); the payload is bounded by the
 * parent UDP length so trailing Ethernet padding is left to the codec's recursion / RawData. A
 * well-formed message round-trips byte-for-byte.
 */
export class Teredo extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Teredo.#schemaCache ??= Teredo.#buildSchema())
    }

    /** Clamp a number into [lo, hi] without throwing (mirrors the fieldUInt clamp contract). */
    static #clamp(value: number, lo: number, hi: number): number {
        if (!Number.isFinite(value)) return lo
        if (value < lo) return lo
        if (value > hi) return hi
        return Math.trunc(value)
    }

    /**
     * Byte length of the Authentication indication header as it exists on the wire / will be written,
     * or 0 when absent. Derived from the client-identifier / authentication-value byte lengths (each
     * capped at 255, a single ID-len/AU-len octet), so decode (where those equal the decoded lengths)
     * and encode compute the SAME offsets for the origin header and the inner payload.
     */
    #authLength(): number {
        if (this.instance.authentication.isUndefined()) return 0
        const authentication: any = this.instance.authentication
        const idLength: number = Math.min(255, HexToBuffer(authentication.clientId.getValue('')).length)
        const auLength: number = Math.min(255, HexToBuffer(authentication.authData.getValue('')).length)
        //2 (type) + 1 (ID-len) + 1 (AU-len) + idLength + auLength + 8 (nonce) + 1 (confirmation).
        return 13 + idLength + auLength
    }

    /** Byte length of the Origin indication header (fixed 8 bytes) or 0 when absent. */
    #originLength(): number {
        return this.instance.origin.isUndefined() ? 0 : 8
    }

    /** Offset where the inner IPv6 payload begins: after whichever indication headers are present. */
    #payloadStart(): number {
        return this.#authLength() + this.#originLength()
    }

    /** End of this Teredo message within the captured bytes, bounded by the parent UDP payload (udp.length − 8). */
    #payloadEnd(): number {
        let end: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpLength: number = prev.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < end) end = udpLength - 8
        }
        return end < 0 ? 0 : end
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Teredo IPv6-over-UDP',
            properties: {
                //Authentication indication (RFC 4380 §5.1.1), present only when the payload starts with
                //Indicator Type 0x0001. The decode/encode logic lives on this parent object; the child
                //properties are declarative (UI form metadata) so they are not decoded a second time.
                authentication: {
                    type: 'object',
                    label: 'Authentication Indication',
                    properties: {
                        clientIdLength: {type: 'integer', label: 'Client ID Length', minimum: 0, maximum: 255},
                        authDataLength: {type: 'integer', label: 'Authentication Value Length', minimum: 0, maximum: 255},
                        clientId: {type: 'string', label: 'Client Identifier', contentEncoding: StringContentEncodingEnum.HEX},
                        authData: {type: 'string', label: 'Authentication Value', contentEncoding: StringContentEncodingEnum.HEX},
                        nonce: {type: 'string', label: 'Nonce', contentEncoding: StringContentEncodingEnum.HEX},
                        confirmation: {type: 'integer', label: 'Confirmation', minimum: 0, maximum: 255}
                    },
                    decode: function (this: Teredo): void {
                        //Peek (dryRun) the indicator type — an inner IPv6 packet starts 0x6X, so only a
                        //genuine Authentication indication reads 0x0001 here.
                        if (BufferToUInt16(this.readBytes(0, 2, true)) !== 0x0001) return
                        const idLength: number = BufferToUInt8(this.readBytes(2, 1, true))
                        const auLength: number = BufferToUInt8(this.readBytes(3, 1, true))
                        //The WHOLE authentication header must fit inside the payload; otherwise this is a
                        //truncated/spoofed prefix — leave the bytes to `payload` so they round-trip verbatim.
                        if (13 + idLength + auLength > this.#payloadEnd()) return
                        const clientId: Buffer = this.readBytes(4, idLength)
                        const authData: Buffer = this.readBytes(4 + idLength, auLength)
                        const nonce: Buffer = this.readBytes(4 + idLength + auLength, 8)
                        const confirmation: number = BufferToUInt8(this.readBytes(12 + idLength + auLength, 1))
                        this.instance.authentication.setValue({
                            clientIdLength: idLength,
                            authDataLength: auLength,
                            clientId: BufferToHex(clientId),
                            authData: BufferToHex(authData),
                            nonce: BufferToHex(nonce),
                            confirmation: confirmation
                        })
                    },
                    encode: function (this: Teredo): void {
                        if (this.instance.authentication.isUndefined()) return
                        const authentication: any = this.instance.authentication
                        //ID-len / AU-len are derived from (and capped to) the actual bytes written, so
                        //the length octets and the following data can never disagree.
                        const clientId: Buffer = HexToBuffer(authentication.clientId.getValue('')).subarray(0, 255)
                        const authData: Buffer = HexToBuffer(authentication.authData.getValue('')).subarray(0, 255)
                        //Nonce is a fixed 8-byte field; pad/truncate so #authLength's constant 13 holds.
                        let nonce: Buffer = HexToBuffer(authentication.nonce.getValue(''))
                        if (nonce.length < 8) nonce = Buffer.concat([nonce, Buffer.alloc(8 - nonce.length, 0)])
                        else if (nonce.length > 8) nonce = nonce.subarray(0, 8)
                        const confirmation: number = Teredo.#clamp(authentication.confirmation.getValue(0), 0, 255)
                        const idLength: number = clientId.length
                        const auLength: number = authData.length
                        this.writeBytes(0, UInt16ToBuffer(0x0001))
                        this.writeBytes(2, UInt8ToBuffer(idLength))
                        this.writeBytes(3, UInt8ToBuffer(auLength))
                        this.writeBytes(4, clientId)
                        this.writeBytes(4 + idLength, authData)
                        this.writeBytes(4 + idLength + auLength, nonce)
                        this.writeBytes(12 + idLength + auLength, UInt8ToBuffer(confirmation))
                    }
                },
                //Origin indication (RFC 4380 §5.1.1), present only when the payload (after any
                //Authentication indication) starts with Indicator Type 0x0000. Port and address are
                //stored de-obfuscated (mapped) and re-obfuscated (XOR) on encode.
                origin: {
                    type: 'object',
                    label: 'Origin Indication',
                    properties: {
                        port: {type: 'integer', label: 'Mapped Port', minimum: 0, maximum: 65535},
                        address: {
                            type: 'string',
                            label: 'Mapped Address',
                            minLength: 7,
                            maxLength: 15,
                            contentEncoding: StringContentEncodingEnum.IPv4
                        }
                    },
                    decode: function (this: Teredo): void {
                        const start: number = this.#authLength()
                        if (BufferToUInt16(this.readBytes(start, 2, true)) !== 0x0000) return
                        //A full 8-byte origin header must fit; otherwise leave the bytes to the payload.
                        if (start + 8 > this.#payloadEnd()) return
                        const wirePort: number = BufferToUInt16(this.readBytes(start + 2, 2))
                        const wireAddress: Buffer = this.readBytes(start + 4, 4)
                        const mappedAddress: Buffer = Buffer.from([
                            wireAddress[0] ^ 0xff,
                            wireAddress[1] ^ 0xff,
                            wireAddress[2] ^ 0xff,
                            wireAddress[3] ^ 0xff
                        ])
                        this.instance.origin.setValue({
                            port: (wirePort ^ 0xffff) & 0xffff,
                            address: BufferToIPv4(mappedAddress)
                        })
                    },
                    encode: function (this: Teredo): void {
                        if (this.instance.origin.isUndefined()) return
                        const start: number = this.#authLength()
                        const origin: any = this.instance.origin
                        const port: number = Teredo.#clamp(origin.port.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found')), 0, 65535)
                        const address: string = origin.address.getValue('0.0.0.0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        const addressBuffer: Buffer = IPv4ToBuffer(address)
                        const wireAddress: Buffer = Buffer.from([
                            addressBuffer[0] ^ 0xff,
                            addressBuffer[1] ^ 0xff,
                            addressBuffer[2] ^ 0xff,
                            addressBuffer[3] ^ 0xff
                        ])
                        this.writeBytes(start, UInt16ToBuffer(0x0000))
                        this.writeBytes(start + 2, UInt16ToBuffer((port ^ 0xffff) & 0xffff))
                        this.writeBytes(start + 4, wireAddress)
                    }
                },
                //The inner IPv6 packet (and anything after the indications), kept verbatim. Bounded by
                //the parent UDP payload, so trailing padding is left to the codec's recursion / RawData.
                //Not recursed into (would need an IPv6.match change) — a later serial step.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: Teredo): void {
                        const start: number = this.#payloadStart()
                        const end: number = this.#payloadEnd()
                        this.instance.payload.setValue(end > start ? BufferToHex(this.readBytes(start, end - start)) : '')
                    },
                    encode: function (this: Teredo): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(this.#payloadStart(), HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'teredo'

    public readonly name: string = 'Teredo IPv6 over UDP tunneling'

    public readonly nickname: string = 'Teredo'

    public readonly matchKeys: string[] = ['udpport:3544']

    public match(): boolean {
        //Teredo rides on UDP port 3544 (the port bucket selects this candidate). Confirm a UDP parent
        //and at least one payload byte; the message is either an inner IPv6 packet or an indication
        //header, both recognised by content inside decode.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        return this.packet.length - this.startPos >= 1
    }

    //A leaf header — the inner IPv6 packet is kept as payload hex (not recursed, see class comment).
    public readonly demuxProducers: DemuxProducer[] = []

}
