import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * WebSocket — the RFC 6455 framing (post-HTTP-Upgrade). A frame is: byte 0 = FIN (1) + 3 reserved bits +
 * a 4-bit Opcode (0 continuation, 1 text, 2 binary, 8 close, 9 ping, 10 pong); byte 1 = MASK (1) + a
 * 7-bit payload length; an extended length (2 bytes if the 7-bit length is 126, 8 bytes if 127); a 4-byte
 * masking key when MASK is set; then the (masked) application payload.
 *
 * WebSocket is NOT auto-registered in the default codec: which TCP stream is a WebSocket is decided by a
 * prior HTTP `Upgrade` handshake — cross-packet state a single-packet stateless codec cannot track — so
 * matching a frame on content alone would over-claim ordinary TCP payloads. It is therefore a
 * decode-as-only frame codec: reachable via `new Codec([WebSocket])` (or a future upgrade-aware
 * reassembly layer). The frame itself round-trips byte-for-byte; the payload is kept verbatim (masked
 * bytes are not unmasked — that would change the bytes and break the round-trip).
 */
export class WebSocket extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (WebSocket.#schemaCache ??= WebSocket.#buildSchema())
    }

    /** Number of extended-length bytes implied by the 7-bit length: 2 for 126, 8 for 127, else 0. */
    #extendedLengthBytes(): number {
        const payloadLen: number = this.instance.payloadLen.getValue(0)
        return payloadLen === 126 ? 2 : payloadLen === 127 ? 8 : 0
    }

    /** Offset where the masking key (if any) begins: after byte 0/1 and the extended length. */
    #maskOffset(): number {
        return 2 + this.#extendedLengthBytes()
    }

    /** Offset where the payload begins: after the masking key when MASK is set. */
    #payloadOffset(): number {
        return this.#maskOffset() + (this.instance.mask.getValue(false) ? 4 : 0)
    }

    /** A single boolean bit within `byteOffset` at MSB-relative `bitOffset`. */
    static #bitField(name: string, byteOffset: number, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'boolean',
            label: label,
            decode: function (this: WebSocket): void {
                (this.instance as any)[name].setValue(!!this.readBits(byteOffset, 1, bitOffset, 1))
            },
            encode: function (this: WebSocket): void {
                this.writeBits(byteOffset, 1, bitOffset, 1, (this.instance as any)[name].getValue(false) ? 1 : 0)
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'WebSocket opcode=${opcode}',
            properties: {
                fin: this.#bitField('fin', 0, 0, 'FIN'),
                rsv1: this.#bitField('rsv1', 0, 1, 'RSV1'),
                rsv2: this.#bitField('rsv2', 0, 2, 'RSV2'),
                rsv3: this.#bitField('rsv3', 0, 3, 'RSV3'),
                opcode: {
                    type: 'integer', label: 'Opcode', minimum: 0, maximum: 15,
                    decode: function (this: WebSocket): void {
                        this.instance.opcode.setValue(this.readBits(0, 1, 4, 4))
                    },
                    encode: function (this: WebSocket): void {
                        let value: number = this.instance.opcode.getValue(0)
                        if (value > 15) value = 15
                        if (value < 0) value = 0
                        this.writeBits(0, 1, 4, 4, value)
                    }
                },
                mask: this.#bitField('mask', 1, 0, 'Mask'),
                payloadLen: {
                    type: 'integer', label: 'Payload Length (7-bit)', minimum: 0, maximum: 127,
                    decode: function (this: WebSocket): void {
                        this.instance.payloadLen.setValue(this.readBits(1, 1, 1, 7))
                    },
                    encode: function (this: WebSocket): void {
                        let value: number = this.instance.payloadLen.getValue(0)
                        if (value > 127) value = 127
                        if (value < 0) value = 0
                        this.writeBits(1, 1, 1, 7, value)
                    }
                },
                //Extended payload length: 2 or 8 bytes (kept verbatim as hex), present per the 7-bit length.
                extendedPayloadLength: {
                    type: 'string', label: 'Extended Payload Length', contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: WebSocket): void {
                        const bytes: number = this.#extendedLengthBytes()
                        this.instance.extendedPayloadLength.setValue(bytes > 0 ? BufferToHex(this.readBytes(2, bytes)) : '')
                    },
                    encode: function (this: WebSocket): void {
                        const value: string = this.instance.extendedPayloadLength.getValue('')
                        if (value) this.writeBytes(2, HexToBuffer(value))
                    }
                },
                //4-byte masking key, present only when MASK is set.
                maskingKey: {
                    type: 'string', label: 'Masking Key', contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: WebSocket): void {
                        if (!this.instance.mask.getValue(false)) return
                        this.instance.maskingKey.setValue(BufferToHex(this.readBytes(this.#maskOffset(), 4)))
                    },
                    encode: function (this: WebSocket): void {
                        if (!this.instance.mask.getValue(false)) return
                        const value: string = this.instance.maskingKey.getValue('')
                        if (value) this.writeBytes(this.#maskOffset(), HexToBuffer(value))
                    }
                },
                //The application payload, kept verbatim (masked bytes are NOT unmasked — that would alter
                //the wire bytes and break the round-trip). Length is the 7-bit length, or the extended
                //length, bounded by the captured bytes.
                payload: {
                    type: 'string', label: 'Payload', contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: WebSocket): void {
                        const offset: number = this.#payloadOffset()
                        const available: number = this.packet.length - this.startPos
                        const payloadLen: number = this.instance.payloadLen.getValue(0)
                        const extended: string = this.instance.extendedPayloadLength.getValue('')
                        let length: number = extended ? parseInt(extended, 16) : payloadLen
                        if (!Number.isFinite(length) || length < 0) length = 0
                        if (offset + length > available) length = available - offset
                        if (length < 0) length = 0
                        this.instance.payload.setValue(length > 0 ? BufferToHex(this.readBytes(offset, length)) : '')
                    },
                    encode: function (this: WebSocket): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(this.#payloadOffset(), HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'websocket'

    public readonly name: string = 'WebSocket'

    public readonly nickname: string = 'WS'

    //Decode-as-only: no matchKeys (never auto-selected). When explicitly added via new Codec([WebSocket])
    //it claims a TCP payload whose first two bytes are a plausible frame (a valid opcode, no reserved
    //bits) — enough to guard against obvious non-frames while the caller has opted in.
    public readonly matchKeys: string[] = []

    public match(): boolean {
        const prev: any = this.prevCodecModule
        if (!prev || prev.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 2) return false
        const byte0: number = this.readBytes(0, 1, true)[0]
        //Reserved bits must be 0 (no extension negotiated) and the opcode must be a defined one.
        if ((byte0 & 0x70) !== 0) return false
        const opcode: number = byte0 & 0x0f
        return opcode === 0x0 || opcode === 0x1 || opcode === 0x2 || opcode === 0x8 || opcode === 0x9 || opcode === 0xa
    }

    //A leaf — the payload is application data (possibly masked), kept verbatim.
    public readonly demuxProducers: DemuxProducer[] = []

}
