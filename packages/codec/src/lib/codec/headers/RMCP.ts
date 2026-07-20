import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt8ToBuffer, UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * RMCP — Remote Management Control Protocol (ASF 2.0 / DSP0136, IPMI 2.0), UDP port 623. The 4-byte
 * header is Version (0x06 = RMCP 1.0), a Reserved byte, a Sequence Number (0xFF = no ACK requested),
 * and a Class-of-Message byte whose top bit is the ACK flag, bit 6 is reserved, and the low 6 bits are
 * the message class (6 = ASF, 7 = IPMI, 8 = OEM).
 *
 * The payload after the header depends on the class. For an ASF message (class 6) the payload is an
 * ASF frame — IANA Enterprise Number (4542 for ASF), Message Type, Message Tag, a reserved byte, a
 * Data Length, and the data — which this codec decodes structurally (the trailing data is kept as raw
 * hex so any length rounds-trips). For IPMI (7, a session-wrapped message) and OEM (8) classes the
 * payload is kept verbatim (rawBody) — those are stateful session protocols for a higher layer. A
 * well-formed message round-trips byte-for-byte.
 */
export class RMCP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (RMCP.#schemaCache ??= RMCP.#buildSchema())
    }

    /** The payload length bounded by the UDP datagram (so a retained FCS/padding is not absorbed). */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'RMCP class=${messageClass.class} seq=${sequence}',
            properties: {
                version: this.fieldUInt('version', 0, 1, 'Version'),
                reserved: this.fieldHex('reserved', 1, 1, 'Reserved'),
                sequence: this.fieldUInt('sequence', 2, 1, 'Sequence Number'),
                //Class-of-Message byte (ASF DSP0136 / IPMI, MSB first): bit 7 = ACK flag, bits 6:5 =
                //reserved (2 bits, kept for byte-perfect), bits 4:0 = message class (6 = ASF, 7 = IPMI,
                //8 = OEM). readBits' bitOffset 0 = MSB, so ACK is bitOffset 0, reserved 1..2, class 3..7.
                messageClass: {
                    type: 'object',
                    label: 'Class of Message',
                    properties: {
                        ack: {
                            type: 'boolean',
                            label: 'ACK',
                            decode: function (this: RMCP): void { this.instance.messageClass.ack.setValue(!!this.readBits(3, 1, 0, 1)) },
                            encode: function (this: RMCP): void {
                                const ack: boolean = !!this.instance.messageClass.ack.getValue()
                                this.instance.messageClass.ack.setValue(ack)
                                this.writeBits(3, 1, 0, 1, ack ? 1 : 0)
                            }
                        },
                        reserved: {
                            type: 'integer',
                            label: 'Reserved',
                            minimum: 0,
                            maximum: 3,
                            hidden: true,
                            decode: function (this: RMCP): void { this.instance.messageClass.reserved.setValue(this.readBits(3, 1, 1, 2)) },
                            encode: function (this: RMCP): void { this.writeBits(3, 1, 1, 2, this.instance.messageClass.reserved.getValue(0)) }
                        },
                        class: {
                            type: 'integer',
                            label: 'Message Class',
                            minimum: 0,
                            maximum: 31,
                            decode: function (this: RMCP): void { this.instance.messageClass.class.setValue(this.readBits(3, 1, 3, 5)) },
                            encode: function (this: RMCP): void { this.writeBits(3, 1, 3, 5, this.instance.messageClass.class.getValue(0)) }
                        }
                    }
                },
                //Class-driven payload: an ASF message (class 6) is decoded structurally; every other class
                //(IPMI session, OEM) is kept verbatim. Runs after messageClass so the class is known.
                asf: {
                    type: 'object',
                    label: 'ASF Message',
                    properties: {
                        enterprise: {type: 'integer', label: 'IANA Enterprise Number', minimum: 0, maximum: 4294967295},
                        type: {type: 'integer', label: 'Message Type', minimum: 0, maximum: 255},
                        tag: {type: 'integer', label: 'Message Tag', minimum: 0, maximum: 255},
                        reserved: {type: 'string', label: 'Reserved', contentEncoding: StringContentEncodingEnum.HEX},
                        dataLength: {type: 'integer', label: 'Data Length', minimum: 0, maximum: 255},
                        data: {type: 'string', label: 'Data', contentEncoding: StringContentEncodingEnum.HEX}
                    },
                    decode: function (this: RMCP): void {
                        const available: number = this.#payloadLength()
                        const classValue: number = this.instance.messageClass.class.getValue(0)
                        //ASF class with a full 8-byte ASF header present (enterprise+type+tag+reserved+len).
                        if (classValue === 6 && available >= 12) {
                            this.instance.asf.enterprise.setValue(BufferToUInt32(this.readBytes(4, 4)))
                            this.instance.asf.type.setValue(BufferToUInt8(this.readBytes(8, 1)))
                            this.instance.asf.tag.setValue(BufferToUInt8(this.readBytes(9, 1)))
                            this.instance.asf.reserved.setValue(BufferToHex(this.readBytes(10, 1)))
                            this.instance.asf.dataLength.setValue(BufferToUInt8(this.readBytes(11, 1)))
                            this.instance.asf.data.setValue(available > 12 ? BufferToHex(this.readBytes(12, available - 12)) : '')
                            this.instance.rawBody.setValue('')
                            return
                        }
                        //IPMI / OEM / a too-short ASF frame: keep the payload verbatim.
                        this.instance.rawBody.setValue(available > 4 ? BufferToHex(this.readBytes(4, available - 4)) : '')
                    },
                    encode: function (this: RMCP): void {
                        //A verbatim body (IPMI/OEM, or a short-ASF fallback) is re-emitted as-is and wins.
                        const rawBody: string = this.instance.rawBody.getValue('')
                        if (rawBody) {
                            this.writeBytes(4, HexToBuffer(rawBody))
                            return
                        }
                        //Only emit an ASF header when one was actually decoded/provided (the mandatory
                        //Enterprise Number is present). A bare 4-byte class-6 payload (e.g. an ASF-class
                        //RMCP ACK: 06 00 seq 86) has no ASF message and must NOT gain phantom bytes.
                        const classValue: number = this.instance.messageClass.class.getValue(0)
                        const enterprise: number | undefined = this.instance.asf.enterprise.getValue()
                        if (classValue !== 6 || enterprise === undefined || enterprise === null) return
                        this.writeBytes(4, UInt32ToBuffer(enterprise))
                        this.writeBytes(8, UInt8ToBuffer(this.instance.asf.type.getValue(0)))
                        this.writeBytes(9, UInt8ToBuffer(this.instance.asf.tag.getValue(0)))
                        this.writeBytes(10, HexToBuffer(this.instance.asf.reserved.getValue('00')))
                        this.writeBytes(11, UInt8ToBuffer(this.instance.asf.dataLength.getValue(0)))
                        const data: string = this.instance.asf.data.getValue('')
                        if (data) this.writeBytes(12, HexToBuffer(data))
                    }
                },
                rawBody: {type: 'string', label: 'Body', contentEncoding: StringContentEncodingEnum.HEX, hidden: true}
            }
        }
    }

    public readonly id: string = 'rmcp'

    public readonly name: string = 'Remote Management Control Protocol'

    public readonly nickname: string = 'RMCP'

    public readonly matchKeys: string[] = ['udpport:623']

    public match(): boolean {
        //Require the 4-byte RMCP header within the UDP payload (a shorter datagram on port 623 is not
        //an RMCP message and must fall through to raw rather than claim an un-decodable layer).
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp' && this.#payloadLength() >= 4
    }

    //A leaf header — the IPMI session/OEM payloads are stateful and belong to a higher layer.
    public readonly demuxProducers: DemuxProducer[] = []

}
