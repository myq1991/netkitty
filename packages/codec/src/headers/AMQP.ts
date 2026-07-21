import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16, BufferToUInt32} from '../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer, UInt32ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** The 8-byte literal a client sends first to negotiate the protocol: "AMQP" + 4 version octets. */
const PROTOCOL_HEADER_MAGIC: Buffer = Buffer.from('AMQP', 'latin1') // 41 4d 51 50
/** AMQP frame end marker — every frame terminates with this octet (AMQP 0-9-1 §2.3.5). */
const FRAME_END: number = 0xce
/** Valid frame type octets: 1=METHOD, 2=HEADER, 3=BODY, 8=HEARTBEAT (AMQP 0-9-1 §2.3.5). */
const FRAME_TYPES: number[] = [1, 2, 3, 8]

/**
 * AMQP 0-9-1 — the Advanced Message Queuing Protocol as spoken by RabbitMQ and friends, carried over TCP
 * port 5672. A connection opens with an 8-byte protocol header — the literal "AMQP" followed by four
 * version octets (0 0 9 1 for 0-9-1) — sent once at connection start to negotiate the version. Everything
 * after that is a stream of frames: a 1-byte type (1=METHOD, 2=HEADER, 3=BODY, 8=HEARTBEAT), a 2-byte
 * channel, a 4-byte payload length, `length` payload octets, and a single 0xCE frame-end octet.
 *
 * This codec handles BOTH forms in one header (they are distinguished on the wire by the leading "AMQP"
 * literal). The protocol-header handshake decodes to {isProtocolHeader:true, protocol:'AMQP', + the four
 * version octets}; a frame decodes to type/channel/length/payload/frameEnd. The frame payload carries a
 * class/method id and its arguments (METHOD), a content-header (HEADER), or opaque bytes (BODY) — decoding
 * those is cross-frame, class-dependent state, so this minimal slice keeps the payload verbatim as hex
 * (byte-perfect). The payload is bounded by the length field (the frame ends at offset 7+length, with the
 * frame-end octet there), so a pipelined second frame or trailing bytes are left to the codec's recursion
 * / RawData. Length is honored when supplied on encode (a crafted frame may lie), else derived from the
 * payload bytes. A well-formed handshake or frame round-trips byte-for-byte.
 */
export class AMQP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (AMQP.#schemaCache ??= AMQP.#buildSchema())
    }

    /** True when this instance is (being) decoded/encoded as the 8-byte protocol-header handshake. */
    #isHandshake(): boolean {
        return Boolean(this.instance.isProtocolHeader.getValue(false))
    }

    /**
     * A version octet of the protocol-header handshake (one of the four bytes after the "AMQP" literal,
     * at `offset`). Only present in the handshake form: decode reads it when this is a handshake; encode
     * writes it only when this is a handshake, so a frame never emits these bytes.
     */
    static #versionField(name: string, offset: number, label: string, defaultValue: number): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 255,
            default: defaultValue,
            decode: function (this: AMQP): void {
                if (!this.#isHandshake()) return
                ;(this.instance as any)[name].setValue(BufferToUInt8(this.readBytes(offset, 1)))
            },
            encode: function (this: AMQP): void {
                if (!this.#isHandshake()) return
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(defaultValue, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > 255) {
                    this.recordError(node.getPath(), 'Maximum value is 255')
                    value = 255
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(offset, UInt8ToBuffer(value))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            //Two forms share one summary slot; `info` is a decode-only display field set to
            //'protocol-header' for the handshake or 'type=<n>' for a frame (see the isProtocolHeader
            //field below), so the rendered Info column reads "AMQP protocol-header" or "AMQP type=1".
            summary: 'AMQP ${info}',
            properties: {
                //Discriminator + display. Decode inspects the first four octets: the "AMQP" literal marks
                //the handshake, anything else is a frame. This field also fills the decode-only `info`
                //display string (it needs the raw type octet, which it reads directly). On encode it is
                //an input value (default false) that every other field branches on; it writes no bytes.
                isProtocolHeader: {
                    type: 'boolean',
                    label: 'Is Protocol Header',
                    default: false,
                    decode: function (this: AMQP): void {
                        const lead: Buffer = this.readBytes(0, 4, true)
                        const handshake: boolean = lead.length >= 4 && lead.equals(PROTOCOL_HEADER_MAGIC)
                        this.instance.isProtocolHeader.setValue(handshake)
                        this.instance.info.setValue(handshake ? 'protocol-header' : `type=${BufferToUInt8(this.readBytes(0, 1, true))}`)
                    }
                },
                //Decode-only display string for the Info summary (populated above); carries no encode, so
                //it never affects the emitted bytes.
                info: {type: 'string', label: 'Info'},

                // ===== Protocol-header handshake form ("AMQP" + four version octets) =====
                protocol: {
                    type: 'string',
                    label: 'Protocol',
                    default: 'AMQP',
                    decode: function (this: AMQP): void {
                        if (!this.#isHandshake()) return
                        this.instance.protocol.setValue(this.readBytes(0, 4).toString('latin1'))
                    },
                    encode: function (this: AMQP): void {
                        if (!this.#isHandshake()) return
                        //Re-emit the 4-char literal verbatim (default "AMQP"); truncate/pad to 4 octets so
                        //a crafted value can never shift the version octets that follow.
                        const text: string = this.instance.protocol.getValue('AMQP')
                        const bytes: Buffer = Buffer.alloc(4, 0)
                        Buffer.from(text, 'latin1').copy(bytes, 0, 0, 4)
                        this.writeBytes(0, bytes)
                    }
                },
                //The four version octets after the literal: protocol-id, major, minor, revision (0 0 9 1).
                protocolId: this.#versionField('protocolId', 4, 'Protocol Id', 0),
                versionMajor: this.#versionField('versionMajor', 5, 'Version Major', 0),
                versionMinor: this.#versionField('versionMinor', 6, 'Version Minor', 9),
                versionRevision: this.#versionField('versionRevision', 7, 'Version Revision', 1),

                // ===== Frame form (type + channel + length + payload + frameEnd) =====
                type: {
                    type: 'integer',
                    label: 'Type',
                    minimum: 0,
                    maximum: 255,
                    default: 1,
                    decode: function (this: AMQP): void {
                        if (this.#isHandshake()) return
                        this.instance.type.setValue(BufferToUInt8(this.readBytes(0, 1)))
                    },
                    encode: function (this: AMQP): void {
                        if (this.#isHandshake()) return
                        const node: any = this.instance.type
                        let value: number = node.getValue(1, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 255) {
                            this.recordError(node.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBytes(0, UInt8ToBuffer(value))
                    }
                },
                channel: {
                    type: 'integer',
                    label: 'Channel',
                    minimum: 0,
                    maximum: 65535,
                    default: 0,
                    decode: function (this: AMQP): void {
                        if (this.#isHandshake()) return
                        this.instance.channel.setValue(BufferToUInt16(this.readBytes(1, 2)))
                    },
                    encode: function (this: AMQP): void {
                        if (this.#isHandshake()) return
                        const node: any = this.instance.channel
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 65535) {
                            this.recordError(node.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBytes(1, UInt16ToBuffer(value))
                    }
                },
                //NOTE: Length is honored verbatim on encode (a crafted frame may lie), and the frameEnd is
                //written at offset 7+Length, which auto-expands the buffer. A deliberately crafted Length near
                //0xFFFFFFFF therefore drives a multi-GB allocation on re-encode — an instance of the codebase's
                //general "writeBytes auto-expand vs read-clamp asymmetry on attacker-controlled length fields"
                //(a scheduled hardening item at the BaseHeader level, wider here because the field is uint32 vs
                //ENIP's uint16). It does not break the never-throws contract (the RangeError is caught and
                //recorded), and a well-formed frame (Length == payload bytes) never triggers it.
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: AMQP): void {
                        if (this.#isHandshake()) return
                        this.instance.length.setValue(BufferToUInt32(this.readBytes(3, 4)))
                    },
                    encode: function (this: AMQP): void {
                        if (this.#isHandshake()) return
                        //Length counts the payload octets between the header and the frame-end marker.
                        //Honored when supplied (a crafted frame may lie); else derived from the payload.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.payload.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(3, UInt32ToBuffer(value))
                    }
                },
                //The frame payload, kept verbatim. Bounded by the length field (payload ends at offset
                //7+length) and the captured bytes, so a pipelined/trailing frame is left to the codec's
                //recursion / RawData.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: AMQP): void {
                        if (this.#isHandshake()) return
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        let end: number = 7 + length
                        if (end > remaining) end = remaining
                        this.instance.payload.setValue(end > 7 ? BufferToHex(this.readBytes(7, end - 7)) : '')
                    },
                    encode: function (this: AMQP): void {
                        if (this.#isHandshake()) return
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(7, HexToBuffer(payload))
                    }
                },
                frameEnd: {
                    type: 'integer',
                    label: 'Frame End',
                    minimum: 0,
                    maximum: 255,
                    default: FRAME_END,
                    decode: function (this: AMQP): void {
                        if (this.#isHandshake()) return
                        const length: number = this.instance.length.getValue(0)
                        this.instance.frameEnd.setValue(BufferToUInt8(this.readBytes(7 + length, 1)))
                    },
                    encode: function (this: AMQP): void {
                        if (this.#isHandshake()) return
                        //Sits right after the payload; its offset depends on the length written above
                        //(the length field encodes before this one), so re-derive the same length.
                        const provided: number | undefined = this.instance.length.getValue()
                        const length: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.payload.getValue('')).length
                        const node: any = this.instance.frameEnd
                        let value: number = node.getValue(FRAME_END, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 255) {
                            this.recordError(node.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBytes(7 + length, UInt8ToBuffer(value))
                    }
                }
            }
        }
    }

    public readonly id: string = 'amqp'

    public readonly name: string = 'AMQP 0-9-1'

    public readonly nickname: string = 'AMQP'

    public readonly matchKeys: string[] = ['tcpport:5672']

    //Deliberately NOT a heuristicFallback: an AMQP frame header (type/channel/length) carries no strong
    //content magic — a bare 1/2/3/8 type octet over a plausible channel/length would collide with all
    //manner of binary TCP payloads — so recognition is confined to the well-known port bucket (5672).
    //The "AMQP" literal is a strong signature, but it only appears on the one-shot connection handshake,
    //not on ongoing frames, so it cannot carry the protocol off-port on its own.
    public readonly heuristicFallback: boolean = false

    public match(): boolean {
        //AMQP rides on TCP port 5672. Accept either the connection-start protocol-header literal ("AMQP")
        //or a frame whose leading octet is a known frame type with the fixed 7-byte header present.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        const remaining: number = this.packet.length - this.startPos
        if (remaining < 1) return false
        if (remaining >= 4 && this.readBytes(0, 4, true).equals(PROTOCOL_HEADER_MAGIC)) return true
        return remaining >= 8 && FRAME_TYPES.includes(BufferToUInt8(this.readBytes(0, 1, true)))
    }

    //A leaf header — the frame payload (class/method arguments, content headers, body) is cross-frame,
    //class-dependent state kept as hex, not demuxed further.
    public readonly demuxProducers: DemuxProducer[] = []

}
