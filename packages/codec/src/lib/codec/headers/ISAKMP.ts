import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16, BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer, UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * One ISAKMP/IKE generic payload (RFC 7296 §3.2): its own Next Payload pointer, the critical bit + the
 * remaining reserved bits, the 2-byte Payload Length (includes the 4-byte generic header), and the body
 * kept verbatim as hex (structuring per-payload-type bodies is a later slice).
 */
type ISAKMPPayload = {nextPayload: number, critical: boolean, reserved: number, payloadLength: number, body: string}

/**
 * ISAKMP / IKE — Internet Security Association and Key Management Protocol carrying IKEv1 (RFC 2408 /
 * RFC 2409) and IKEv2 (RFC 7296), UDP port 500 (NAT-T also uses 4500 with a 4-byte non-ESP marker
 * prefix — out of scope for this slice, which matches port 500 only). A 28-byte fixed header (all
 * big-endian): the 8-byte Initiator and 8-byte Responder SPIs (cookies), a Next Payload selector, a
 * split Version byte (high nibble = major, low nibble = minor; IKEv1 is 0x10, IKEv2 is 0x20), the
 * Exchange Type, a flags byte, the 4-byte Message ID, and the 4-byte total message Length (header +
 * all payloads). The header is followed by a chain of generic payloads walked via each payload's own
 * Next Payload / Payload Length until Next Payload == 0 (or the message Length / UDP payload is
 * consumed).
 *
 * Payloads are carried generically (Next Payload + critical/reserved + length + verbatim body hex) so
 * every payload — SA proposals, KE, Nonce, encrypted payloads — round-trips byte-for-byte; per-payload
 * semantic decoding is a later enrichment. The chain walk is bounded by the message Length (honored
 * else derived on encode) clamped by the UDP payload, so any trailing bytes spill to the raw layer.
 */
export class ISAKMP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (ISAKMP.#schemaCache ??= ISAKMP.#buildSchema())
    }

    /** Bytes available for this ISAKMP message: the frame end, clamped by the UDP payload and the message Length. */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        //During match() the Length field is not yet decoded (getValue → 0), so this reduces to the
        //UDP-payload bound; during decode it is set and tightens the payload-chain walk.
        const length: number = this.instance.length.getValue(0)
        if (length >= 28 && length < available) available = length
        return available < 0 ? 0 : available
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'ISAKMP exch=${exchangeType}',
            properties: {
                initiatorSPI: this.fieldHex('initiatorSPI', 0, 8, 'Initiator SPI'),
                responderSPI: this.fieldHex('responderSPI', 8, 8, 'Responder SPI'),
                nextPayload: this.fieldUInt('nextPayload', 16, 1, 'Next Payload'),
                //Version byte (offset 17): high nibble = major, low nibble = minor. IKEv1 = 1.0 (0x10),
                //IKEv2 = 2.0 (0x20). Split into nibbles (lossless: the whole byte is major+minor).
                version: {
                    type: 'object',
                    label: 'Version',
                    properties: {
                        major: {
                            type: 'integer', label: 'Major', minimum: 0, maximum: 15,
                            decode: function (this: ISAKMP): void { this.instance.version.major.setValue(this.readBits(17, 1, 0, 4)) },
                            encode: function (this: ISAKMP): void { this.writeBits(17, 1, 0, 4, this.instance.version.major.getValue(2)) }
                        },
                        minor: {
                            type: 'integer', label: 'Minor', minimum: 0, maximum: 15,
                            decode: function (this: ISAKMP): void { this.instance.version.minor.setValue(this.readBits(17, 1, 4, 4)) },
                            encode: function (this: ISAKMP): void { this.writeBits(17, 1, 4, 4, this.instance.version.minor.getValue(0)) }
                        }
                    }
                },
                exchangeType: this.fieldUInt('exchangeType', 18, 1, 'Exchange Type'),
                //Flags byte (offset 19) kept whole: IKEv2 uses bit X(0x08 Initiator)/V(0x10 Version)/
                //R(0x20 Response); IKEv1 uses E/C/A. Carried verbatim so any flag combination round-trips.
                flags: this.fieldUInt('flags', 19, 1, 'Flags'),
                messageId: this.fieldUInt('messageId', 20, 4, 'Message ID'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: ISAKMP): void {
                        this.instance.length.setValue(BufferToUInt32(this.readBytes(24, 4)))
                    },
                    encode: function (this: ISAKMP): void {
                        //Honor an explicitly-set Length (even a decoded malformed one, so it round-trips
                        //byte-for-byte); auto-compute the whole-message length only when absent (crafting).
                        const length: number | undefined = this.instance.length.getValue()
                        if (length !== undefined && length !== null) {
                            this.instance.length.setValue(length)
                            this.writeBytes(24, UInt32ToBuffer(length))
                        } else {
                            this.writeBytes(24, UInt32ToBuffer(0))
                            //After the payload chain has encoded, the header length is the whole message.
                            this.addPostSelfEncodeHandler((): void => {
                                this.instance.length.setValue(this.length)
                                this.writeBytes(24, UInt32ToBuffer(this.length))
                            }, 1)
                        }
                    }
                },
                payloads: {
                    type: 'array',
                    label: 'Payloads',
                    items: {
                        type: 'object',
                        label: 'Payload',
                        properties: {
                            nextPayload: {type: 'integer', label: 'Next Payload', minimum: 0, maximum: 255},
                            critical: {type: 'boolean', label: 'Critical'},
                            reserved: {type: 'integer', label: 'Reserved', minimum: 0, maximum: 127, hidden: true},
                            payloadLength: {type: 'integer', label: 'Payload Length', minimum: 0, maximum: 65535},
                            body: {type: 'string', label: 'Body', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: ISAKMP): void {
                        const end: number = this.#available()
                        const payloads: ISAKMPPayload[] = []
                        let offset: number = 28
                        //The header's Next Payload selects the first payload's type; each generic payload
                        //header's own Next Payload selects the following one — the chain ends at 0. Probe
                        //the 4-byte generic header (dry) first; a Payload Length < 4 (would not advance) or
                        //one that overruns the message stops the walk and leaves the rest to the raw layer.
                        let next: number = this.instance.nextPayload.getValue(0)
                        while (next !== 0 && offset + 4 <= end) {
                            const payloadNext: number = BufferToUInt8(this.readBytes(offset, 1, true))
                            const criticalReserved: number = BufferToUInt8(this.readBytes(offset + 1, 1, true))
                            const payloadLength: number = BufferToUInt16(this.readBytes(offset + 2, 2, true))
                            if (payloadLength < 4 || offset + payloadLength > end) break
                            const payloadBuffer: Buffer = this.readBytes(offset, payloadLength)
                            payloads.push({
                                nextPayload: payloadNext,
                                critical: !!(criticalReserved & 0x80),
                                reserved: criticalReserved & 0x7f,
                                payloadLength: payloadLength,
                                body: payloadLength > 4 ? BufferToHex(payloadBuffer.subarray(4)) : ''
                            })
                            offset += payloadLength
                            next = payloadNext
                        }
                        this.instance.payloads.setValue(payloads)
                    },
                    encode: function (this: ISAKMP): void {
                        const payloads: ISAKMPPayload[] = this.instance.payloads.getValue([])
                        if (!payloads) return
                        let offset: number = 28
                        for (const payload of payloads) {
                            const body: Buffer = HexToBuffer(payload.body ? payload.body : '')
                            //Honor an explicit Payload Length (byte-perfect for decoded frames), else derive
                            //it from the body (4-byte generic header + body).
                            const payloadLength: number = (payload.payloadLength !== undefined && payload.payloadLength !== null)
                                ? payload.payloadLength
                                : body.length + 4
                            const criticalReserved: number = (payload.critical ? 0x80 : 0) | ((payload.reserved ? payload.reserved : 0) & 0x7f)
                            this.writeBytes(offset, UInt8ToBuffer(payload.nextPayload ? payload.nextPayload : 0))
                            this.writeBytes(offset + 1, UInt8ToBuffer(criticalReserved))
                            this.writeBytes(offset + 2, UInt16ToBuffer(payloadLength))
                            offset += 4
                            if (body.length) {
                                this.writeBytes(offset, body)
                                offset += body.length
                            }
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'isakmp'

    public readonly name: string = 'ISAKMP/IKE'

    public readonly nickname: string = 'ISAKMP'

    public readonly matchKeys: string[] = ['udpport:500']

    public match(): boolean {
        //Require the full 28-byte fixed header within the UDP payload, a plausible message Length (>= the
        //header itself), and a major-version nibble of 1 (IKEv1) or 2 (IKEv2) — anything else on port 500
        //(e.g. an IKE NAT keepalive 0xff, or unrelated traffic) falls through to raw. No heuristic
        //fallback: the port bucket plus this signature is the sole selector.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.#available() < 28) return false
        const length: number = BufferToUInt32(this.readBytes(24, 4, true))
        if (length < 28) return false
        const major: number = this.readBytes(17, 1, true)[0] >> 4
        return major === 1 || major === 2
    }

    //A leaf header — payload bodies are carried verbatim; nothing demuxes above ISAKMP in this slice.
    public readonly demuxProducers: DemuxProducer[] = []

}
