import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt8ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * MQTT-SN — MQTT for Sensor Networks (v1.2), the UDP-datagram publish/subscribe protocol for
 * constrained/wireless sensor networks (commonly gateway UDP ports 1883 or 10000). NOT to be confused
 * with MQTT itself, which is the TCP/1883 stream protocol handled by the separate `mqtt` header.
 *
 * Every message begins with a variable-length Length field: the first octet is either the whole
 * message length (1..255, counting the Length field itself + the Message Type + the body), OR the
 * escape value 0x01, in which case the next TWO octets are the real length as a big-endian uint16
 * (used when the message is 256..65535 octets). The Length is followed by a 1-octet Message Type
 * (0x00 ADVERTISE, 0x04 CONNECT, 0x05 CONNACK, 0x0C PUBLISH, 0x12 SUBSCRIBE, …) and then the
 * type-specific body.
 *
 * Because the per-type body layout (flags, topic ids/names, QoS, will) is message-type dependent and,
 * for PUBLISH/SUBSCRIBE, ties into cross-datagram topic-registration state, this single-datagram codec
 * keeps the body verbatim as `body` hex (byte-perfect) and does not sub-decode it. The Length is
 * honored when supplied (a crafted datagram may lie), else derived from the body; the wire form (1- vs
 * 3-octet Length) is derived from the Length value (>255 ⇒ 3-octet escape form), matching how a
 * conformant sender chooses it, so a well-formed datagram round-trips byte-for-byte. The message is
 * bounded by its Length and the UDP payload, so trailing bytes fall through to the codec's recursion /
 * RawData.
 */
export class MQTTSN extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (MQTTSN.#schemaCache ??= MQTTSN.#buildSchema())
    }

    /** The MQTT-SN message length bounded by the UDP datagram (so retained FCS/padding is not absorbed). */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /** Wire size of the Length field as seen on decode: the escape octet 0x01 ⇒ 3-octet form, else 1-octet. */
    #decodePrefixSize(): number {
        return BufferToUInt8(this.readBytes(0, 1, true)) === 0x01 ? 3 : 1
    }

    /** Wire size of the Length field for a given Length value: >255 needs the 3-octet escape form. */
    static #prefixSizeFor(length: number): number {
        return length > 255 ? 3 : 1
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'MQTT-SN type=${msgType} len=${length}',
            properties: {
                //The whole-message octet count (Length field + Message Type + body). 1-octet on the wire
                //when <256, else the 0x01 escape octet followed by a big-endian uint16. Honored when
                //supplied (a crafted datagram may lie); else derived from the body byte length.
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: MQTTSN): void {
                        if (this.#payloadLength() < 1) {
                            this.instance.length.setValue(0)
                            return
                        }
                        const b0: number = BufferToUInt8(this.readBytes(0, 1))
                        //Escape form: the next 2 octets are the real length (big-endian). readBytes
                        //clamps at the buffer end and BufferToUInt16 tolerates a short read, so a
                        //truncated escape-form Length never throws.
                        this.instance.length.setValue(b0 === 0x01 ? BufferToUInt16(this.readBytes(1, 2)) : b0)
                    },
                    encode: function (this: MQTTSN): void {
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number
                        if (provided !== undefined && provided !== null) {
                            value = provided
                        } else {
                            //Derive: whole-message = 1-octet-Length(1) + Message Type(1) + body. If that
                            //overflows the 1-octet form (>255) the escape form adds 2 more Length octets.
                            const bodyLength: number = HexToBuffer(this.instance.body.getValue('')).length
                            value = 2 + bodyLength
                            if (value > 255) value = 4 + bodyLength
                        }
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        if (value > 255) {
                            this.writeBytes(0, Buffer.from([0x01, (value >> 8) & 0xff, value & 0xff]))
                        } else {
                            this.writeBytes(0, UInt8ToBuffer(value))
                        }
                    }
                },
                //Message Type octet (0x00 ADVERTISE, 0x04 CONNECT, 0x05 CONNACK, 0x0C PUBLISH, 0x12
                //SUBSCRIBE, …). Kept as a plain uint so any on-wire type value round-trips.
                msgType: {
                    type: 'integer',
                    label: 'Message Type',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: MQTTSN): void {
                        this.instance.msgType.setValue(BufferToUInt8(this.readBytes(this.#decodePrefixSize(), 1)))
                    },
                    encode: function (this: MQTTSN): void {
                        const node: any = this.instance.msgType
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 255) {
                            this.recordError(node.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBytes(MQTTSN.#prefixSizeFor(this.instance.length.getValue(0)), UInt8ToBuffer(value))
                    }
                },
                //The type-specific body after the Length + Message Type, kept verbatim. Bounded by the
                //message Length and the UDP payload, so trailing/pipelined data is left to the codec's
                //recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: MQTTSN): void {
                        const prefix: number = this.#decodePrefixSize()
                        const available: number = this.#payloadLength()
                        let end: number = this.instance.length.getValue(0)
                        if (end > available) end = available
                        const bodyStart: number = prefix + 1
                        this.instance.body.setValue(end > bodyStart ? BufferToHex(this.readBytes(bodyStart, end - bodyStart)) : '')
                    },
                    encode: function (this: MQTTSN): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(MQTTSN.#prefixSizeFor(this.instance.length.getValue(0)) + 1, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'mqttsn'

    public readonly name: string = 'MQTT for Sensor Networks'

    public readonly nickname: string = 'MQTT-SN'

    //MQTT-SN rides UDP at gateway ports 1883 / 10000. It carries no fixed content magic (the first
    //octet is a length), so selection stays port-bucketed with a minimum-length guard; no
    //heuristicFallback (a length-led header has no signature reliable enough to claim arbitrary ports).
    public readonly matchKeys: string[] = ['udpport:1883', 'udpport:10000']

    public match(): boolean {
        //Require at least the minimal 1-octet Length + Message Type within the UDP payload, so a shorter
        //datagram on the port falls through to raw rather than claiming an un-decodable layer.
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp' && this.#payloadLength() >= 2
    }

    //A leaf header — the per-type body needs message-type-dependent, cross-datagram parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
