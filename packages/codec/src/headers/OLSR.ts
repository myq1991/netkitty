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
 * One OLSR message: the 12-byte message header (Message Type, Vtime, Message Size, Originator Address,
 * Time To Live, Hop Count, Message Sequence Number) plus its type-specific body kept verbatim as hex.
 */
type OlsrMessage = {
    messageType: number,
    vTime: number,
    messageSize: number,
    originatorAddress: string,
    ttl: number,
    hopCount: number,
    messageSeqNo: number,
    body: string
}

/**
 * OLSR — Optimized Link State Routing (RFC 3626), a MANET proactive routing protocol carried over UDP
 * port 698. An OLSR packet is a 4-byte packet header — Packet Length (the total packet octet count
 * including this header) and Packet Sequence Number — followed by one or more messages. Each message is
 * a 12-byte message header — Message Type (1 HELLO, 2 TC, 3 MID, 4 HNA), Vtime (the validity-time
 * mantissa/exponent byte), Message Size (the message octet count including this 12-byte header),
 * Originator Address (the 4-byte IPv4 address of the node that generated the message), Time To Live,
 * Hop Count and Message Sequence Number — followed by (Message Size - 12) body bytes.
 *
 * The message body layout differs per Message Type (HELLO's link/neighbor sets, TC's advertised
 * neighbors, MID's interface addresses, HNA's network/mask pairs) and several bodies need
 * cross-message topology context, so this codec keeps each body verbatim as `body` hex (byte-perfect)
 * and does not sub-decode it. The message array runs from offset 4 to the Packet Length (capped by the
 * UDP payload), each message bounded by its own Message Size; a message that under/overruns is not
 * consumed, so trailing / truncated bytes are left to the codec's recursion / RawData. On encode the
 * Packet Length and each Message Size are honored when supplied (a crafted packet may lie), else derived
 * from the actual bytes. A well-formed packet round-trips byte-for-byte.
 */
export class OLSR extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (OLSR.#schemaCache ??= OLSR.#buildSchema())
    }

    /** The payload length bounded by the UDP datagram (so retained padding/FCS is not absorbed). */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /** Byte offset the message walk stops at: min(UDP payload, Packet Length). */
    #consumedEnd(): number {
        const payload: number = this.#payloadLength()
        const packetLength: number = this.instance.packetLength.getValue(0)
        return (packetLength > 0 && packetLength < payload) ? packetLength : payload
    }

    /** Clamp a crafted numeric field to [0, max], recording an error rather than throwing or wrapping. */
    #clamp(path: string, value: number | undefined, max: number): number {
        let v: number = (value === undefined || value === null) ? 0 : value
        if (v > max) {
            this.recordError(path, `Maximum value is ${max}`)
            v = max
        }
        if (v < 0) {
            this.recordError(path, 'Minimum value is 0')
            v = 0
        }
        return v
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'OLSR seq=${packetSequenceNumber} ${messages.length} msgs',
            properties: {
                packetLength: {
                    type: 'integer',
                    label: 'Packet Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: OLSR): void {
                        this.instance.packetLength.setValue(BufferToUInt16(this.readBytes(0, 2)))
                    },
                    encode: function (this: OLSR): void {
                        //Packet Length counts the whole packet = 4-byte header + every message. Honored
                        //when supplied (a crafted packet may lie); else derived from the actual message
                        //bytes (12-byte header + body each), matching what the `messages` field writes.
                        const provided: number | undefined = this.instance.packetLength.getValue()
                        let value: number
                        if (provided !== undefined && provided !== null) {
                            value = provided
                        } else {
                            const messages: OlsrMessage[] = this.instance.messages.getValue([])
                            let total: number = 4
                            if (messages) {
                                for (const message of messages) {
                                    total += 12 + HexToBuffer(message.body ? message.body : '').length
                                }
                            }
                            value = total
                        }
                        if (value > 65535) {
                            this.recordError(this.instance.packetLength.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.packetLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.packetLength.setValue(value)
                        this.writeBytes(0, UInt16ToBuffer(value))
                    }
                },
                packetSequenceNumber: this.fieldUInt('packetSequenceNumber', 2, 2, 'Packet Sequence Number'),
                //The message chain — 12-byte header + body each, running from offset 4 to the Packet
                //Length (capped by the UDP payload). Owns a single offset walk; each body is bounded by
                //its own Message Size and kept verbatim so every message round-trips byte-for-byte.
                messages: {
                    type: 'array',
                    label: 'Messages',
                    items: {
                        type: 'object',
                        label: 'Message',
                        properties: {
                            //Wire fields are plain integers (no hard enum) so any on-wire value re-encodes.
                            messageType: {type: 'integer', label: 'Message Type', minimum: 0, maximum: 255},
                            vTime: {type: 'integer', label: 'Vtime', minimum: 0, maximum: 255},
                            messageSize: {type: 'integer', label: 'Message Size', minimum: 0, maximum: 65535},
                            originatorAddress: {type: 'string', label: 'Originator Address', minLength: 7, maxLength: 15, contentEncoding: StringContentEncodingEnum.IPv4},
                            ttl: {type: 'integer', label: 'Time To Live', minimum: 0, maximum: 255},
                            hopCount: {type: 'integer', label: 'Hop Count', minimum: 0, maximum: 255},
                            messageSeqNo: {type: 'integer', label: 'Message Sequence Number', minimum: 0, maximum: 65535},
                            body: {type: 'string', label: 'Body', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: OLSR): void {
                        const end: number = this.#consumedEnd()
                        const messages: OlsrMessage[] = []
                        let offset: number = 4
                        while (offset + 12 <= end) {
                            //Peek the Message Size (dry-run, so it does not extend the consumed header
                            //length) to decide whether the whole message fits. A message that claims fewer
                            //than its 12-byte header, or overruns the packet, is truncation/corruption —
                            //stop and leave the remaining bytes to the codec's recursion / RawData.
                            const messageSize: number = BufferToUInt16(this.readBytes(offset + 2, 2, true))
                            if (messageSize < 12 || offset + messageSize > end) break
                            const messageType: number = BufferToUInt8(this.readBytes(offset, 1))
                            const vTime: number = BufferToUInt8(this.readBytes(offset + 1, 1))
                            const originatorAddress: string = BufferToIPv4(this.readBytes(offset + 4, 4))
                            const ttl: number = BufferToUInt8(this.readBytes(offset + 8, 1))
                            const hopCount: number = BufferToUInt8(this.readBytes(offset + 9, 1))
                            const messageSeqNo: number = BufferToUInt16(this.readBytes(offset + 10, 2))
                            const body: string = messageSize > 12 ? BufferToHex(this.readBytes(offset + 12, messageSize - 12)) : ''
                            messages.push({
                                messageType: messageType,
                                vTime: vTime,
                                messageSize: messageSize,
                                originatorAddress: originatorAddress,
                                ttl: ttl,
                                hopCount: hopCount,
                                messageSeqNo: messageSeqNo,
                                body: body
                            })
                            offset += messageSize
                        }
                        this.instance.messages.setValue(messages)
                    },
                    encode: function (this: OLSR): void {
                        const messages: OlsrMessage[] = this.instance.messages.getValue([])
                        if (!messages) return
                        let offset: number = 4
                        for (let i: number = 0; i < messages.length; i++) {
                            const message: OlsrMessage = messages[i]
                            const bodyBuffer: Buffer = HexToBuffer(message.body ? message.body : '')
                            //Message Size counts the 12-byte header + body. Honored when supplied (a crafted
                            //message may lie); else derived from the header + body actually written. The walk
                            //advances by the bytes actually written so a lying Size cannot shift the next
                            //message.
                            const messageSize: number = (message.messageSize !== undefined && message.messageSize !== null)
                                ? this.#clamp(`messages[${i}].messageSize`, message.messageSize, 65535)
                                : 12 + bodyBuffer.length
                            this.writeBytes(offset, UInt8ToBuffer(this.#clamp(`messages[${i}].messageType`, message.messageType, 255)))
                            this.writeBytes(offset + 1, UInt8ToBuffer(this.#clamp(`messages[${i}].vTime`, message.vTime, 255)))
                            this.writeBytes(offset + 2, UInt16ToBuffer(messageSize))
                            this.writeBytes(offset + 4, IPv4ToBuffer(message.originatorAddress ? message.originatorAddress : '0.0.0.0'))
                            this.writeBytes(offset + 8, UInt8ToBuffer(this.#clamp(`messages[${i}].ttl`, message.ttl, 255)))
                            this.writeBytes(offset + 9, UInt8ToBuffer(this.#clamp(`messages[${i}].hopCount`, message.hopCount, 255)))
                            this.writeBytes(offset + 10, UInt16ToBuffer(this.#clamp(`messages[${i}].messageSeqNo`, message.messageSeqNo, 65535)))
                            if (bodyBuffer.length) this.writeBytes(offset + 12, bodyBuffer)
                            offset += 12 + bodyBuffer.length
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'olsr'

    public readonly name: string = 'Optimized Link State Routing'

    public readonly nickname: string = 'OLSR'

    public readonly matchKeys: string[] = ['udpport:698']

    public match(): boolean {
        //OLSR rides on UDP port 698. Require the full 4-byte packet header within the UDP payload; a
        //shorter datagram on port 698 is not an OLSR packet and falls through to raw rather than
        //claiming a layer. Selection stays port-bucketed (matchKeys) — the packet header carries no
        //distinctive content magic.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        return this.#payloadLength() >= 4
    }

    //A leaf header — each message body needs per-type, topology-dependent parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
