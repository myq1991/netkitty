import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16, BufferToUInt32} from '../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer, UInt32ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * IAX2 — Inter-Asterisk eXchange version 2 (RFC 5456), the Asterisk VoIP signalling + media trunking
 * protocol, UDP port 4569. Every IAX2 datagram carries exactly one frame whose first bit (the F bit,
 * the MSB of octet 0) selects the frame format:
 *
 *  - Full frame (F = 1) — a 12-byte header: F(1) + Source Call Number(15) | R(1, retransmit) +
 *    Destination Call Number(15) | Timestamp(32) | OSeqno(8) | ISeqno(8) | Frame Type(8) | C(1) +
 *    Subclass(7), followed by the frame data (the Information Elements of a NEW/AUTHREQ/… command, or a
 *    media payload). Full frames are reliably delivered and carry the call-control state.
 *  - Mini frame (F = 0) — a 4-byte header: F(1) + Source Call Number(15) | Timestamp(16), followed by
 *    the media payload. Mini frames carry audio with a truncated 16-bit timestamp to save bandwidth.
 *
 * Byte-perfect strategy (minimal slice): the format is chosen by peeking the MSB of octet 0; the fixed
 * header is bit-unpacked field by field and the frame data is kept verbatim as `data` hex. IAX2 has no
 * in-frame length field — one frame occupies the whole UDP payload — so `data` runs to the transport
 * payload end (udp.length − 8, clamped to the captured bytes so Ethernet padding is not consumed). Every
 * wire field is a plain clamped integer (no Ajv enum), so a crafted / non-conformant value decoded off
 * the wire re-encodes without being rejected — decode never fails and encode is a faithful executor. A
 * well-formed frame round-trips byte-for-byte.
 */
export class IAX2 extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (IAX2.#schemaCache ??= IAX2.#buildSchema())
    }

    /**
     * Header-relative end offset of the transport payload available to this frame, so a decode never
     * reads past the real UDP payload and trailing Ethernet padding is left to the codec. Over UDP the
     * bound is (udp.length − 8); clamped to what was actually captured.
     */
    #payloadEnd(): number {
        let end: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpLength: number = prev.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < end) end = udpLength - 8
        }
        return end < 0 ? 0 : end
    }

    /** True when the frame currently being decoded/encoded is a Full frame (F bit set). */
    #isFull(): boolean {
        return this.instance.fullFrame.getValue() === true
    }

    /**
     * An unsigned integer bit-field present ONLY in Full frames (R bit, Destination Call Number, the C
     * bit, the Subclass). Decode/encode no-op on a Mini frame so those keys never appear, keeping the
     * Mini decode result minimal and its re-encode byte-exact.
     */
    static #fullBits(name: string, offset: number, length: number, bitOffset: number, bitLength: number, label: string): ProtocolFieldJSONSchema {
        const maximum: number = 2 ** bitLength - 1
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: maximum,
            decode: function (this: IAX2): void {
                if (!this.#isFull()) return
                ;(this.instance as any)[name].setValue(this.readBits(offset, length, bitOffset, bitLength))
            },
            encode: function (this: IAX2): void {
                if (!this.#isFull()) return
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > maximum) {
                    this.recordError(node.getPath(), `Maximum value is ${maximum}`)
                    value = maximum
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBits(offset, length, bitOffset, bitLength, value)
            }
        }
    }

    /**
     * An unsigned big-endian integer byte-field present ONLY in Full frames (OSeqno, ISeqno, Frame
     * Type). Decode/encode no-op on a Mini frame.
     */
    static #fullUInt(name: string, offset: number, byteLength: number, label: string): ProtocolFieldJSONSchema {
        const maximum: number = byteLength === 1 ? 255 : 65535
        const read: (buffer: Buffer) => number = byteLength === 1 ? BufferToUInt8 : BufferToUInt16
        const write: (value: number) => Buffer = byteLength === 1 ? UInt8ToBuffer : UInt16ToBuffer
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: maximum,
            decode: function (this: IAX2): void {
                if (!this.#isFull()) return
                ;(this.instance as any)[name].setValue(read(this.readBytes(offset, byteLength)))
            },
            encode: function (this: IAX2): void {
                if (!this.#isFull()) return
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > maximum) {
                    this.recordError(node.getPath(), `Maximum value is ${maximum}`)
                    value = maximum
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(offset, write(value))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'IAX2 src=${sourceCall} ts=${timestamp}',
            properties: {
                //F bit (MSB of octet 0): true => Full frame (12-byte header), false => Mini frame (4-byte
                //header). Decoded first so every following field can branch on the frame format.
                fullFrame: {
                    type: 'boolean',
                    label: 'Full Frame',
                    decode: function (this: IAX2): void {
                        this.instance.fullFrame.setValue(this.readBits(0, 1, 0, 1) === 1)
                    },
                    encode: function (this: IAX2): void {
                        const value: boolean = this.instance.fullFrame.getValue() === true
                        this.instance.fullFrame.setValue(value)
                        this.writeBits(0, 1, 0, 1, value ? 1 : 0)
                    }
                },
                //Source Call Number: the low 15 bits of the first 2 octets. Present in BOTH formats.
                sourceCall: {
                    type: 'integer',
                    label: 'Source Call Number',
                    minimum: 0,
                    maximum: 32767,
                    decode: function (this: IAX2): void {
                        this.instance.sourceCall.setValue(this.readBits(0, 2, 1, 15))
                    },
                    encode: function (this: IAX2): void {
                        const node: any = this.instance.sourceCall
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 32767) {
                            this.recordError(node.getPath(), 'Maximum value is 32767')
                            value = 32767
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBits(0, 2, 1, 15, value)
                    }
                },
                //Retransmit (R) bit — MSB of octet 2. Full frames only.
                retransmit: this.#fullBits('retransmit', 2, 1, 0, 1, 'Retransmit'),
                //Destination Call Number: the low 15 bits of octets 2..3. Full frames only.
                destCall: this.#fullBits('destCall', 2, 2, 1, 15, 'Destination Call Number'),
                //Timestamp: 32-bit (Full, octets 4..7) or 16-bit truncated (Mini, octets 2..3). A single
                //field whose width/offset follow the frame format; the Ajv maximum stays at the 32-bit
                //ceiling so a decoded Full timestamp is never rejected on re-encode.
                timestamp: {
                    type: 'integer',
                    label: 'Timestamp',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: IAX2): void {
                        if (this.#isFull()) {
                            this.instance.timestamp.setValue(BufferToUInt32(this.readBytes(4, 4)))
                        } else {
                            this.instance.timestamp.setValue(BufferToUInt16(this.readBytes(2, 2)))
                        }
                    },
                    encode: function (this: IAX2): void {
                        const full: boolean = this.#isFull()
                        const maximum: number = full ? 4294967295 : 65535
                        const node: any = this.instance.timestamp
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > maximum) {
                            this.recordError(node.getPath(), `Maximum value is ${maximum}`)
                            value = maximum
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        if (full) this.writeBytes(4, UInt32ToBuffer(value))
                        else this.writeBytes(2, UInt16ToBuffer(value))
                    }
                },
                //Outbound stream sequence number (octet 8). Full frames only.
                oSeqno: this.#fullUInt('oSeqno', 8, 1, 'Outbound Sequence Number'),
                //Inbound stream sequence number (octet 9). Full frames only.
                iSeqno: this.#fullUInt('iSeqno', 9, 1, 'Inbound Sequence Number'),
                //Frame Type (octet 10): 1 DTMF, 2 Voice, 4 Control, 6 IAX, 7 Text, … Full frames only.
                //Kept as a plain clamped byte (no Ajv enum) so any crafted value round-trips.
                frameType: this.#fullUInt('frameType', 10, 1, 'Frame Type'),
                //C bit — MSB of octet 11. When set, the Subclass is interpreted as 2^Subclass. Preserved
                //verbatim so the frame round-trips regardless of interpretation. Full frames only.
                subclassC: this.#fullBits('subclassC', 11, 1, 0, 1, 'Subclass Is Power Of Two (C)'),
                //Subclass: low 7 bits of octet 11 — the command within the Frame Type (e.g. NEW=1 within
                //Frame Type 6 IAX). Full frames only.
                subclass: this.#fullBits('subclass', 11, 1, 1, 7, 'Subclass'),
                //The frame data after the fixed header (Full: from octet 12; Mini: from octet 4), kept
                //verbatim. IAX2 has no in-frame length field, so it runs to the transport payload end
                //(udp.length − 8, clamped to the captured bytes), leaving trailing padding to the codec.
                data: {
                    type: 'string',
                    label: 'Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: IAX2): void {
                        const headerLength: number = this.#isFull() ? 12 : 4
                        const end: number = this.#payloadEnd()
                        this.instance.data.setValue(end > headerLength ? BufferToHex(this.readBytes(headerLength, end - headerLength)) : '')
                    },
                    encode: function (this: IAX2): void {
                        const headerLength: number = this.#isFull() ? 12 : 4
                        const data: string = this.instance.data.getValue('')
                        if (data) this.writeBytes(headerLength, HexToBuffer(data))
                        else this.readBytes(headerLength, 0)
                    }
                }
            }
        }
    }

    public readonly id: string = 'iax2'

    public readonly name: string = 'Inter-Asterisk eXchange v2'

    public readonly nickname: string = 'IAX2'

    //IAX2 rides UDP port 4569. No content magic (the F bit alone is not distinctive), so this stays a
    //pure port-bucket protocol: matchKeys only, no heuristicFallback.
    public readonly matchKeys: string[] = ['udpport:4569']

    public match(): boolean {
        //Selected via the udpport:4569 bucket. Require the transport payload to hold the full fixed
        //header for the frame format the F bit announces — 4 bytes for a Mini frame, 12 for a Full
        //frame — so a short datagram on 4569 falls through to raw and the always-re-emitted Full header
        //never breaks the byte round-trip. The payload bound is the UDP payload (udp.length − 8), not
        //the captured frame, so Ethernet padding is not mistaken for header bytes.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        const end: number = this.#payloadEnd()
        if (end < 4) return false
        const full: boolean = (BufferToUInt8(this.readBytes(0, 1, true)) & 0x80) !== 0
        if (full && end < 12) return false
        return true
    }

    //A leaf header — the frame data (IAX2 Information Elements or the media payload) requires
    //Frame-Type- and Subclass-dependent parsing layered on top of this faithful base.
    public readonly demuxProducers: DemuxProducer[] = []

}
