import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt8} from '../helper/BufferToNumber'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * MQTT — Message Queuing Telemetry Transport (OASIS MQTT 3.1.1 / 5.0), a lightweight publish/subscribe
 * messaging protocol on TCP port 1883 (8883 for TLS). Every Control Packet begins with a 2-to-5 byte
 * Fixed Header: a first byte carrying the 4-bit Message Type (1 CONNECT, 2 CONNACK, 3 PUBLISH, 8
 * SUBSCRIBE, 12 PINGREQ, 13 PINGRESP, 14 DISCONNECT, …) and 4 header Flags (for PUBLISH these are
 * DUP / QoS(2 bits) / RETAIN; for every other type they are a fixed reserved value), followed by the
 * Remaining Length — a 1-to-4 byte variable-length integer counting the bytes of the Variable Header
 * plus Payload that follow.
 *
 * This codec decodes the Fixed Header structurally (message type, the flags nibble, and the decoded
 * Remaining Length value) and keeps the Variable Header + Payload region verbatim as `payload` hex —
 * sub-decoding it depends on the message type and, for PUBLISH/SUBSCRIBE, on session/topic state that is
 * cross-packet, not a single-packet concern. The Remaining Length is re-emitted as a canonical varint on
 * encode: honored when supplied, else derived from the payload byte length. Because valid MQTT uses the
 * minimal (canonical) varint encoding, a well-formed packet round-trips byte-for-byte; a hand-crafted
 * frame that used a non-minimal (redundant) varint would not reproduce those extra continuation bytes.
 */
export class MQTT extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (MQTT.#schemaCache ??= MQTT.#buildSchema())
    }

    //Byte length of the Remaining Length varint for the current packet. Set when the remainingLength
    //field decodes/encodes and read by the payload field to locate the start of the Variable Header +
    //Payload region (offset 1 + this many bytes). Per-instance; decode/encode create fresh instances.
    #varintLength: number = 1

    /** Decode the Remaining Length variable-length integer at `offset` (MQTT algorithm: low 7 bits are
     * value, high bit 0x80 means "more bytes follow", up to 4 bytes). Returns the decoded value and how
     * many bytes it occupied. */
    #readRemainingLength(offset: number): {value: number, byteLength: number} {
        let value: number = 0
        let multiplier: number = 1
        let byteLength: number = 0
        for (let i: number = 0; i < 4; i++) {
            const byte: number = BufferToUInt8(this.readBytes(offset + i, 1))
            value += (byte & 0x7f) * multiplier
            multiplier *= 128
            byteLength++
            if ((byte & 0x80) === 0) break
        }
        return {value: value, byteLength: byteLength}
    }

    /** Encode `value` as a canonical (minimal) MQTT Remaining Length varint. */
    #writeRemainingLength(value: number): Buffer {
        const bytes: number[] = []
        let remaining: number = value >= 0 ? value : 0
        do {
            let encodedByte: number = remaining % 128
            remaining = Math.floor(remaining / 128)
            if (remaining > 0) encodedByte |= 0x80
            bytes.push(encodedByte)
        } while (remaining > 0 && bytes.length < 4)
        return Buffer.from(bytes)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'MQTT type=${messageType}',
            properties: {
                //First byte, high nibble (bits 7-4): the Control Packet type.
                messageType: {
                    type: 'integer',
                    label: 'Message Type',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: MQTT): void {
                        this.instance.messageType.setValue(this.readBits(0, 1, 0, 4))
                    },
                    encode: function (this: MQTT): void {
                        this.writeBits(0, 1, 0, 4, this.instance.messageType.getValue(0))
                    }
                },
                //First byte, low nibble (bits 3-0): the header flags. For PUBLISH these are DUP / QoS(2) /
                //RETAIN; for other types a fixed reserved value. Kept as the raw nibble (byte-perfect).
                flags: {
                    type: 'integer',
                    label: 'Flags',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: MQTT): void {
                        this.instance.flags.setValue(this.readBits(0, 1, 4, 4))
                    },
                    encode: function (this: MQTT): void {
                        this.writeBits(0, 1, 4, 4, this.instance.flags.getValue(0))
                    }
                },
                //The decoded value of the Remaining Length varint (length of Variable Header + Payload).
                remainingLength: {
                    type: 'integer',
                    label: 'Remaining Length',
                    minimum: 0,
                    maximum: 268435455,
                    decode: function (this: MQTT): void {
                        const result: {value: number, byteLength: number} = this.#readRemainingLength(1)
                        this.#varintLength = result.byteLength
                        this.instance.remainingLength.setValue(result.value)
                    },
                    encode: function (this: MQTT): void {
                        //Honored when supplied (a crafted packet may carry any value); else derived from the
                        //payload byte length. Re-emitted as a canonical varint — reproduces the wire bytes
                        //for well-formed (minimally encoded) frames.
                        const provided: number | undefined = this.instance.remainingLength.getValue()
                        const value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.payload.getValue('')).length
                        this.instance.remainingLength.setValue(value)
                        const varint: Buffer = this.#writeRemainingLength(value)
                        this.#varintLength = varint.length
                        this.writeBytes(1, varint)
                    }
                },
                //Variable Header + Payload, kept verbatim. Starts after the fixed header (offset 1 + the
                //varint bytes) and spans Remaining Length bytes, clamped to the captured bytes so a
                //truncated frame stays in-bounds and trailing/pipelined data is left to the codec's recursion.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: MQTT): void {
                        const remaining: number = this.packet.length - this.startPos
                        const start: number = 1 + this.#varintLength
                        const length: number = this.instance.remainingLength.getValue(0)
                        let end: number = start + length
                        if (end > remaining) end = remaining
                        this.instance.payload.setValue(end > start ? BufferToHex(this.readBytes(start, end - start)) : '')
                    },
                    encode: function (this: MQTT): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(1 + this.#varintLength, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'mqtt'

    public readonly name: string = 'MQTT'

    public readonly nickname: string = 'MQTT'

    public readonly matchKeys: string[] = ['tcpport:1883']

    public match(): boolean {
        //MQTT rides on TCP port 1883. Require at least the 2-byte minimum Fixed Header and a plausible
        //Control Packet type (1..15; 0 is forbidden) as a content signature so non-MQTT 1883 traffic
        //falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 2) return false
        const byte0: number = BufferToUInt8(this.readBytes(0, 1, true))
        const messageType: number = byte0 >> 4
        return messageType >= 1 && messageType <= 15
    }

    //A leaf header — the Variable Header + Payload is kept as hex, not demuxed further.
    public readonly demuxProducers: DemuxProducer[] = []

}
