import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * CoAP — Constrained Application Protocol (RFC 7252), a RESTful transfer protocol for constrained nodes
 * and networks (IoT), riding on UDP port 5683. Every message opens with a 4-byte fixed header: byte 0
 * holds the 2-bit Version (always 1), a 2-bit Type (0 CON, 1 NON, 2 ACK, 3 RST) and a 4-bit Token
 * Length (TKL, 0-8); byte 1 is the 8-bit Code (a 3-bit class '.' 5-bit detail, e.g. 0.01 GET = 0x01,
 * 2.05 Content = 0x45); bytes 2-3 are the big-endian Message ID. The fixed header is followed by a
 * Token of TKL octets, then a sequence of Options, then optionally a 0xFF payload marker and the
 * payload.
 *
 * This codec decodes the fixed header and the Token structurally and keeps everything after the Token
 * (the Options plus the optional payload-marker-and-payload) verbatim as `payload` hex — de-structuring
 * CoAP's option deltas / TLV encoding is a later slice, so those bytes are preserved untouched and the
 * message round-trips byte-for-byte. The region is bounded by the UDP datagram length so any trailing
 * padding is not absorbed. version === 1 is the content signature that separates a real CoAP datagram
 * on port 5683 from arbitrary traffic.
 */
export class CoAP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (CoAP.#schemaCache ??= CoAP.#buildSchema())
    }

    /** The UDP payload length bounded by the datagram (so retained padding is not absorbed). */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /** The Token octet count, clamped to the spec's 0-8 range and to the bytes actually available. */
    #tokenBytes(): number {
        let count: number = this.instance.tokenLength.getValue(0)
        if (count > 8) count = 8
        if (count < 0) count = 0
        const available: number = this.#payloadLength()
        if (4 + count > available) count = available - 4
        return count < 0 ? 0 : count
    }

    /** A fixed-width big-endian bit field within byte 0 (bitOffset 0 = MSB). */
    static #bitField(name: string, bitOffset: number, bitLength: number, maximum: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: maximum,
            decode: function (this: CoAP): void {
                (this.instance as any)[name].setValue(this.readBits(0, 1, bitOffset, bitLength))
            },
            encode: function (this: CoAP): void {
                this.writeBits(0, 1, bitOffset, bitLength, (this.instance as any)[name].getValue(0))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'CoAP type=${type} code=${code}',
            properties: {
                //Byte 0 (MSB first): Version (bits 7:6, always 1), Type (bits 5:4), Token Length (bits 3:0).
                version: this.#bitField('version', 0, 2, 3, 'Version'),
                type: this.#bitField('type', 2, 2, 3, 'Type'),
                tokenLength: this.#bitField('tokenLength', 4, 4, 15, 'Token Length'),
                //Byte 1: Code — a 3-bit class and 5-bit detail packed as one octet (e.g. 0x01 = 0.01 GET).
                code: this.fieldUInt('code', 1, 1, 'Code'),
                //Bytes 2-3: Message ID (big-endian uint16).
                messageId: this.fieldUInt('messageId', 2, 2, 'Message ID'),
                //Token: TKL octets immediately after the fixed header, kept verbatim as hex ('' when TKL 0).
                token: {
                    type: 'string',
                    label: 'Token',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: CoAP): void {
                        const count: number = this.#tokenBytes()
                        this.instance.token.setValue(count > 0 ? BufferToHex(this.readBytes(4, count)) : '')
                    },
                    encode: function (this: CoAP): void {
                        const token: string = this.instance.token.getValue('')
                        if (token) this.writeBytes(4, HexToBuffer(token))
                    }
                },
                //Options + optional payload-marker-and-payload, kept verbatim (TLV de-structuring is a later
                //slice). Bounded by the UDP datagram, and placed right after the Token (offset 4 + TKL).
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: CoAP): void {
                        const available: number = this.#payloadLength()
                        const start: number = 4 + this.#tokenBytes()
                        this.instance.payload.setValue(start < available ? BufferToHex(this.readBytes(start, available - start)) : '')
                    },
                    encode: function (this: CoAP): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) {
                            //The actual token bytes are authoritative for where the payload starts (the
                            //token field writes its own bytes at offset 4), so the payload cannot overlap
                            //or gap the token even when a crafted Token Length disagrees with the token.
                            const tokenBytes: number = HexToBuffer(this.instance.token.getValue('')).length
                            this.writeBytes(4 + tokenBytes, HexToBuffer(payload))
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'coap'

    public readonly name: string = 'Constrained Application Protocol'

    public readonly nickname: string = 'CoAP'

    public readonly matchKeys: string[] = ['udpport:5683']

    public match(): boolean {
        //CoAP rides on UDP port 5683. Require the 4-byte fixed header within the datagram and the
        //Version == 1 content signature (bits 7:6 of byte 0) so a non-CoAP datagram on 5683 falls
        //through to raw rather than claiming an un-decodable layer.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.#payloadLength() < 4) return false
        const version: number = this.readBits(0, 1, 0, 2)
        return version === 1
    }

    //A leaf header — CoAP option/payload TLV de-structuring is deferred to a later slice.
    public readonly demuxProducers: DemuxProducer[] = []

}
