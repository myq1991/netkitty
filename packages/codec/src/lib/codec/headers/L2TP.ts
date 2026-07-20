import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {CodecModule} from '../types/CodecModule'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One L2TP Attribute-Value Pair (RFC 2661 §4.1). */
type L2TPAVP = {mandatory: boolean, hidden: boolean, reserved: number, vendorId: number, attrType: number, value: string}

/**
 * L2TP — Layer Two Tunneling Protocol, version 2 (RFC 2661), UDP port 1701. The header begins with a
 * 2-byte flags/version field: T (0=data / 1=control), L (Length present), S (Ns/Nr present), O (Offset
 * present), P (Priority), and a 4-bit Version (=2). Depending on the flags the header then carries an
 * optional Length, the Tunnel ID and Session ID, optional Ns/Nr sequence numbers, and an optional
 * Offset (size + pad). A control message (T=1) carries a list of AVPs (each: M/H flags + 10-bit length,
 * Vendor ID, Attribute Type, value); a data message (T=0) carries the tunneled payload, kept as raw hex
 * (it is a leaf here — the tunneled PPP frame is a stateful conversation for a higher layer).
 *
 * A well-formed message round-trips byte-for-byte. The reserved flag bits and AVP reserved bits are
 * normalized to 0 on re-encode (they MUST be 0 per RFC 2661), and an AVP's length is derived from its
 * value; both hold for standard-conformant traffic.
 */
export class L2TP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (L2TP.#schemaCache ??= L2TP.#buildSchema())
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

    /** A single flag bit within the 2-byte flags field (bit 0 = MSB of byte 0). */
    static #flagBit(name: string, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'boolean',
            label: label,
            decode: function (this: L2TP): void {
                (this.instance.flags as any)[name].setValue(!!this.readBits(0, 1, bitOffset, 1))
            },
            encode: function (this: L2TP): void {
                const value: boolean = !!(this.instance.flags as any)[name].getValue()
                ;(this.instance.flags as any)[name].setValue(value)
                this.writeBits(0, 1, bitOffset, 1, value ? 1 : 0)
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'L2TP ${flags.type} tid=${tunnelId} sid=${sessionId}',
            properties: {
                //Flags/version field (byte 0-1, MSB first): T(0) L(1) rsvd(2-3) S(4) rsvd(5) O(6) P(7),
                //then rsvd(8-11) and Version(12-15). Reserved bits are normalized to 0 on encode.
                flags: {
                    type: 'object',
                    label: 'Flags',
                    properties: {
                        type: this.#flagBit('type', 0, 'Type (1=control)'),
                        length: this.#flagBit('length', 1, 'Length Present'),
                        sequence: this.#flagBit('sequence', 4, 'Sequence Present'),
                        offset: this.#flagBit('offset', 6, 'Offset Present'),
                        priority: this.#flagBit('priority', 7, 'Priority'),
                        version: {
                            type: 'integer',
                            label: 'Version',
                            minimum: 0,
                            maximum: 15,
                            decode: function (this: L2TP): void { this.instance.flags.version.setValue(this.readBits(1, 1, 4, 4)) },
                            encode: function (this: L2TP): void { this.writeBits(1, 1, 4, 4, this.instance.flags.version.getValue(2)) }
                        },
                        //Reserved bits (byte0 bits 2-3, byte0 bit 5, byte1 bits 8-11). RFC 2661 requires
                        //them 0, but they are captured verbatim so any frame round-trips byte-for-byte.
                        reserved1: {
                            type: 'integer', label: 'Reserved', minimum: 0, maximum: 3, hidden: true,
                            decode: function (this: L2TP): void { this.instance.flags.reserved1.setValue(this.readBits(0, 1, 2, 2)) },
                            encode: function (this: L2TP): void { this.writeBits(0, 1, 2, 2, this.instance.flags.reserved1.getValue(0)) }
                        },
                        reserved2: {
                            type: 'integer', label: 'Reserved', minimum: 0, maximum: 1, hidden: true,
                            decode: function (this: L2TP): void { this.instance.flags.reserved2.setValue(this.readBits(0, 1, 5, 1)) },
                            encode: function (this: L2TP): void { this.writeBits(0, 1, 5, 1, this.instance.flags.reserved2.getValue(0)) }
                        },
                        reserved3: {
                            type: 'integer', label: 'Reserved', minimum: 0, maximum: 15, hidden: true,
                            decode: function (this: L2TP): void { this.instance.flags.reserved3.setValue(this.readBits(1, 1, 0, 4)) },
                            encode: function (this: L2TP): void { this.writeBits(1, 1, 0, 4, this.instance.flags.reserved3.getValue(0)) }
                        }
                    }
                },
                length: {type: 'integer', label: 'Length', minimum: 0, maximum: 65535},
                tunnelId: {type: 'integer', label: 'Tunnel ID', minimum: 0, maximum: 65535},
                sessionId: {type: 'integer', label: 'Session ID', minimum: 0, maximum: 65535},
                ns: {type: 'integer', label: 'Ns', minimum: 0, maximum: 65535},
                nr: {type: 'integer', label: 'Nr', minimum: 0, maximum: 65535},
                offsetSize: {type: 'integer', label: 'Offset Size', minimum: 0, maximum: 65535},
                offsetPad: {type: 'string', label: 'Offset Pad', contentEncoding: StringContentEncodingEnum.HEX, hidden: true},
                avps: {
                    type: 'array',
                    label: 'AVPs',
                    items: {
                        type: 'object',
                        label: 'AVP',
                        properties: {
                            mandatory: {type: 'boolean', label: 'Mandatory'},
                            hidden: {type: 'boolean', label: 'Hidden'},
                            reserved: {type: 'integer', label: 'Reserved', minimum: 0, maximum: 15, hidden: true},
                            vendorId: {type: 'integer', label: 'Vendor ID', minimum: 0, maximum: 65535},
                            attrType: {type: 'integer', label: 'Attribute Type', minimum: 0, maximum: 65535},
                            value: {type: 'string', label: 'Value', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    }
                },
                payload: {type: 'string', label: 'Payload', contentEncoding: StringContentEncodingEnum.HEX, hidden: true},
                //Master field: the header layout is flag-conditional, so the whole message after the flags
                //is parsed/emitted here into the sibling fields above. Runs after `flags` (property order).
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    hidden: true,
                    decode: function (this: L2TP): void {
                        const available: number = this.#payloadLength()
                        const hasLength: boolean = !!this.instance.flags.length.getValue()
                        const hasSeq: boolean = !!this.instance.flags.sequence.getValue()
                        const hasOffset: boolean = !!this.instance.flags.offset.getValue()
                        const isControl: boolean = !!this.instance.flags.type.getValue()
                        let offset: number = 2
                        let msgEnd: number = available
                        if (hasLength && offset + 2 <= available) {
                            const length: number = BufferToUInt16(this.readBytes(offset, 2))
                            this.instance.length.setValue(length)
                            offset += 2
                            //L2TP Length counts the whole message from the flags byte; bound the AVP walk.
                            if (length >= 6 && length <= available) msgEnd = length
                        }
                        if (offset + 2 <= available) { this.instance.tunnelId.setValue(BufferToUInt16(this.readBytes(offset, 2))); offset += 2 }
                        if (offset + 2 <= available) { this.instance.sessionId.setValue(BufferToUInt16(this.readBytes(offset, 2))); offset += 2 }
                        if (hasSeq) {
                            if (offset + 2 <= available) { this.instance.ns.setValue(BufferToUInt16(this.readBytes(offset, 2))); offset += 2 }
                            if (offset + 2 <= available) { this.instance.nr.setValue(BufferToUInt16(this.readBytes(offset, 2))); offset += 2 }
                        }
                        if (hasOffset && offset + 2 <= available) {
                            const offsetSize: number = BufferToUInt16(this.readBytes(offset, 2))
                            this.instance.offsetSize.setValue(offsetSize)
                            offset += 2
                            const padLen: number = offset + offsetSize <= available ? offsetSize : available - offset
                            this.instance.offsetPad.setValue(padLen > 0 ? BufferToHex(this.readBytes(offset, padLen)) : '')
                            offset += padLen > 0 ? padLen : 0
                        }
                        if (isControl) {
                            //Control message: a list of AVPs up to the message end.
                            const avps: L2TPAVP[] = []
                            while (offset + 6 <= msgEnd) {
                                const avpFlags: number = BufferToUInt16(this.readBytes(offset, 2))
                                const avpLen: number = avpFlags & 0x03ff
                                if (avpLen < 6 || offset + avpLen > msgEnd) break
                                avps.push({
                                    mandatory: !!(avpFlags & 0x8000),
                                    hidden: !!(avpFlags & 0x4000),
                                    reserved: (avpFlags >> 10) & 0x0f,
                                    vendorId: BufferToUInt16(this.readBytes(offset + 2, 2)),
                                    attrType: BufferToUInt16(this.readBytes(offset + 4, 2)),
                                    value: avpLen > 6 ? BufferToHex(this.readBytes(offset + 6, avpLen - 6)) : ''
                                })
                                offset += avpLen
                            }
                            this.instance.avps.setValue(avps)
                            //Any bytes the AVP walk could not consume (malformed) are kept verbatim.
                            this.instance.payload.setValue(offset < available ? BufferToHex(this.readBytes(offset, available - offset)) : '')
                        } else {
                            //Data message: the tunneled payload, kept as raw hex.
                            this.instance.payload.setValue(offset < available ? BufferToHex(this.readBytes(offset, available - offset)) : '')
                        }
                    },
                    encode: function (this: L2TP): void {
                        const hasLength: boolean = !!this.instance.flags.length.getValue()
                        const hasSeq: boolean = !!this.instance.flags.sequence.getValue()
                        const hasOffset: boolean = !!this.instance.flags.offset.getValue()
                        const isControl: boolean = !!this.instance.flags.type.getValue()
                        let offset: number = 2
                        let lengthOffset: number = -1
                        if (hasLength) {
                            lengthOffset = offset
                            this.writeBytes(offset, UInt16ToBuffer(this.instance.length.getValue(0)))
                            offset += 2
                        }
                        this.writeBytes(offset, UInt16ToBuffer(this.instance.tunnelId.getValue(0))); offset += 2
                        this.writeBytes(offset, UInt16ToBuffer(this.instance.sessionId.getValue(0))); offset += 2
                        if (hasSeq) {
                            this.writeBytes(offset, UInt16ToBuffer(this.instance.ns.getValue(0))); offset += 2
                            this.writeBytes(offset, UInt16ToBuffer(this.instance.nr.getValue(0))); offset += 2
                        }
                        if (hasOffset) {
                            const offsetPad: Buffer = HexToBuffer(this.instance.offsetPad.getValue(''))
                            this.writeBytes(offset, UInt16ToBuffer(this.instance.offsetSize.getValue(offsetPad.length))); offset += 2
                            if (offsetPad.length) { this.writeBytes(offset, offsetPad); offset += offsetPad.length }
                        }
                        if (isControl) {
                            const avps: L2TPAVP[] = this.instance.avps.getValue([])
                            if (avps) for (let i: number = 0; i < avps.length; i++) {
                                const avp: L2TPAVP = avps[i]
                                const value: Buffer = HexToBuffer(avp.value ? avp.value : '')
                                const avpLen: number = 6 + value.length
                                //The AVP length is a 10-bit field, so a value > 1017 bytes cannot be
                                //represented — record it rather than silently truncating the length.
                                if (avpLen > 0x03ff) this.recordError(this.instance.avps.getPath() + `[${i}].value`, 'AVP too long for the 10-bit length field')
                                const reserved: number = (avp.reserved ? avp.reserved : 0) & 0x0f
                                const avpFlags: number = (avp.mandatory ? 0x8000 : 0) | (avp.hidden ? 0x4000 : 0) | (reserved << 10) | (avpLen & 0x03ff)
                                this.writeBytes(offset, UInt16ToBuffer(avpFlags)); offset += 2
                                this.writeBytes(offset, UInt16ToBuffer(avp.vendorId ? avp.vendorId : 0)); offset += 2
                                this.writeBytes(offset, UInt16ToBuffer(avp.attrType ? avp.attrType : 0)); offset += 2
                                if (value.length) { this.writeBytes(offset, value); offset += value.length }
                            }
                        }
                        const payload: Buffer = HexToBuffer(this.instance.payload.getValue(''))
                        if (payload.length) { this.writeBytes(offset, payload); offset += payload.length }
                        //Fill in the L2TP Length (whole message from the flags byte) if it was not set.
                        if (hasLength && lengthOffset >= 0 && (this.instance.length.getValue() === undefined || this.instance.length.getValue() === null)) {
                            const lengthPos: number = lengthOffset
                            this.addPostPacketEncodeHandler((): void => {
                                let started: boolean = false
                                let total: number = 0
                                this.codecModules.forEach((codecModule: CodecModule): void => {
                                    if (codecModule === this) started = true
                                    if (started) total += codecModule.length
                                })
                                this.instance.length.setValue(total)
                                this.writeBytes(lengthPos, UInt16ToBuffer(total))
                            }, 1)
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'l2tp'

    public readonly name: string = 'Layer Two Tunneling Protocol'

    public readonly nickname: string = 'L2TP'

    public readonly matchKeys: string[] = ['udpport:1701']

    public match(): boolean {
        //Require the minimum data-message header (flags + tunnel + session = 6 bytes) within the UDP
        //payload, and version 2 (RFC 2661) — L2TPv3 has a different structure and falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.#payloadLength() < 6) return false
        return (this.readBytes(1, 1, true)[0] & 0x0f) === 2
    }

    //A leaf header — the tunneled PPP payload / control-plane state belongs to a higher layer.
    public readonly demuxProducers: DemuxProducer[] = []

}
