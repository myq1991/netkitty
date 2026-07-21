import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * SLP — Service Location Protocol Version 2 (RFC 2608), UDP (and TCP) port 427. Every SLPv2 message
 * begins with a common header: an 8-bit Version (2), an 8-bit Function-ID (1 SrvRqst, 2 SrvRply,
 * 3 SrvReg, 4 SrvDeReg, 5 SrvAck, 6 AttrRqst, 7 AttrRply, 8 DAAdvert, 9 SrvTypeRqst, 10 SrvTypeRply,
 * 11 SAAdvert), a 24-bit Length (the entire message octet count including this header), a 16-bit Flags
 * field (bit 0 Overflow, bit 1 Fresh, bit 2 Request-multicast, the remaining 13 bits reserved), a 24-bit
 * Next Extension Offset, a 16-bit XID, a 16-bit Language Tag Length and the Language Tag of that many
 * octets — then the Function-ID-specific body.
 *
 * The body layout differs per Function-ID (SrvRqst's PRList/service-type/scope/predicate/SPL SPI,
 * SrvRply's URL entries, SrvReg's URL + attributes, …) and several sub-structures carry authentication
 * blocks and cross-message context, so this common-header codec keeps the body verbatim as `body` hex
 * (byte-perfect) and does not sub-decode it. The Length is auto-computed on encode when not supplied,
 * else honored verbatim (a crafted message may lie); the Language Tag Length is likewise honor-else-
 * derive. The message is bounded by its Length (and the UDP datagram) so trailing / pipelined bytes are
 * left to the codec's recursion / RawData. A well-formed message round-trips byte-for-byte.
 */
export class SLP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SLP.#schemaCache ??= SLP.#buildSchema())
    }

    /** The UDP payload length bounded by the datagram, so trailing padding is not absorbed. */
    #boundedAvailable(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /** The decoded Language Tag octet count, clamped to what is actually present after the 14-byte header. */
    #langTagBytes(): number {
        let count: number = this.instance.langTagLen.getValue(0)
        if (count < 0) count = 0
        const available: number = this.#boundedAvailable()
        if (14 + count > available) count = available - 14
        return count < 0 ? 0 : count
    }

    /** A plain big-endian unsigned 24-bit field of 3 octets at `offset`. */
    static #fieldUInt24(name: string, offset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 16777215,
            decode: function (this: SLP): void {
                const b: Buffer = this.readBytes(offset, 3)
                ;(this.instance as any)[name].setValue((b[0] << 16) | (b[1] << 8) | b[2])
            },
            encode: function (this: SLP): void {
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > 16777215) {
                    this.recordError(node.getPath(), 'Maximum value is 16777215')
                    value = 16777215
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(offset, Buffer.from([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SLP func=${functionId} xid=${xid}',
            properties: {
                version: this.fieldUInt('version', 0, 1, 'Version'),
                functionId: this.fieldUInt('functionId', 1, 1, 'Function-ID'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 16777215,
                    decode: function (this: SLP): void {
                        const b: Buffer = this.readBytes(2, 3)
                        this.instance.length.setValue((b[0] << 16) | (b[1] << 8) | b[2])
                    },
                    encode: function (this: SLP): void {
                        //Length counts the whole message = 14-byte common header + Language Tag + body.
                        //Honored when supplied (a crafted message may lie); else derived from the fields.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 14 + HexToBuffer(this.instance.langTag.getValue('')).length + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 16777215) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 16777215')
                            value = 16777215
                        }
                        if (value < 0) value = 0
                        this.instance.length.setValue(value)
                        this.writeBytes(2, Buffer.from([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]))
                    }
                },
                //Flags: bit 0 Overflow, bit 1 Fresh, bit 2 Request-multicast; the remaining 13 bits are
                //reserved. Kept as a plain uint16 so reserved bits round-trip; the bit split is UI
                //enrichment for later.
                flags: this.fieldUInt('flags', 5, 2, 'Flags'),
                nextExtOffset: this.#fieldUInt24('nextExtOffset', 7, 'Next Extension Offset'),
                xid: this.fieldUInt('xid', 10, 2, 'XID'),
                langTagLen: {
                    type: 'integer',
                    label: 'Language Tag Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: SLP): void {
                        const b: Buffer = this.readBytes(12, 2)
                        this.instance.langTagLen.setValue((b[0] << 8) | b[1])
                    },
                    encode: function (this: SLP): void {
                        //Length of the Language Tag that follows. Honored when supplied (a crafted message
                        //may lie); else derived from the Language Tag bytes.
                        const provided: number | undefined = this.instance.langTagLen.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.langTag.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.langTagLen.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) value = 0
                        this.instance.langTagLen.setValue(value)
                        this.writeBytes(12, Buffer.from([(value >> 8) & 0xff, value & 0xff]))
                    }
                },
                //The Language Tag (US-ASCII, e.g. "en"), kept verbatim as hex so any tag round-trips
                //byte-for-byte. Bounded by the Language Tag Length and the bytes actually present.
                langTag: {
                    type: 'string',
                    label: 'Language Tag',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SLP): void {
                        const count: number = this.#langTagBytes()
                        this.instance.langTag.setValue(count > 0 ? BufferToHex(this.readBytes(14, count)) : '')
                    },
                    encode: function (this: SLP): void {
                        const langTag: string = this.instance.langTag.getValue('')
                        if (langTag) this.writeBytes(14, HexToBuffer(langTag))
                    }
                },
                //The Function-ID-specific body after the common header + Language Tag, kept verbatim.
                //Bounded by the message Length (the message ends at offset Length) and the captured / UDP
                //bytes, so trailing / pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SLP): void {
                        const available: number = this.#boundedAvailable()
                        const length: number = this.instance.length.getValue(0)
                        let bodyStart: number = 14 + this.#langTagBytes()
                        if (bodyStart > available) bodyStart = available
                        let end: number = length
                        if (end > available) end = available
                        this.instance.body.setValue(end > bodyStart ? BufferToHex(this.readBytes(bodyStart, end - bodyStart)) : '')
                    },
                    encode: function (this: SLP): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(14 + HexToBuffer(this.instance.langTag.getValue('')).length, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'slp'

    public readonly name: string = 'Service Location Protocol'

    public readonly nickname: string = 'SLP'

    public readonly matchKeys: string[] = ['udpport:427', 'tcpport:427']

    public match(): boolean {
        //SLP rides on UDP/TCP port 427 (selected via the udpport:427 / tcpport:427 bucket). Require the
        //full 14-byte common header and Version == 2 (the SLPv2 content signature) so non-SLP 427 traffic
        //falls through to raw.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'udp' && this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 14) return false
        return this.readBytes(0, 1, true)[0] === 2
    }

    //A leaf header — the Function-ID-specific body requires per-type, cross-message parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
