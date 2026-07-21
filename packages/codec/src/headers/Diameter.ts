import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt32} from '../helper/BufferToNumber'
import {UInt8ToBuffer, UInt32ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One Diameter AVP. `length` is the on-wire AVP Length (header + data, NOT padding); `padding` is the
 *  verbatim 4-byte-alignment pad kept so the message round-trips byte-for-byte; `vendorId` is present
 *  only when the V flag (0x80) is set in `flags`. `data` is the value portion as lower-case hex. */
type DiameterAVP = {code: number, flags: number, length: number, vendorId?: number, data: string, padding: string}

/**
 * Diameter (RFC 6733), the RADIUS successor — TCP/SCTP port 3868. A 20-byte fixed header, all
 * big-endian: Version (1, always 1) + Message Length (3, the whole message including the header and the
 * padded AVPs) + Command Flags (1: R/P/E/T in the high nibble) + Command Code (3) + Application-Id (4) +
 * Hop-by-Hop Id (4) + End-to-End Id (4). It is followed by AVPs until the Message Length is consumed.
 *
 * Each AVP is AVP Code(4) + Flags(1: V/M/P) + Length(3, counts the AVP header + data but NOT the trailing
 * padding) + [Vendor-Id(4) only when the V flag 0x80 is set] + data + padding (zero bytes to the next
 * 4-byte boundary). Because the AVP Length excludes the padding, the alignment pad is the tricky part of a
 * byte-perfect round-trip: it is captured verbatim (per AVP, as hex) and re-emitted, so even a malformed
 * non-zero pad reproduces exactly. AVPs are carried generically (code + flags + verbatim hex value) so
 * every AVP — including Grouped AVPs whose value nests sub-AVPs — round-trips; per-AVP semantic decoding
 * is a later enrichment. The walk is bounded by the Message Length (and the captured bytes), so any
 * trailing/pipelined bytes spill to the raw layer.
 *
 * MATCH is a two-signal gate — the well-known port bucket (tcpport:3868) plus a content signature
 * (Version == 1 and a plausible Message Length >= 20) — so there is deliberately NO heuristicFallback:
 * unlike a content-signed protocol (TLS/IEC104), Diameter's first byte (a constant 1) and 3-byte length
 * are far too weak a signature to claim arbitrary off-port TCP traffic, so recognition stays anchored to
 * the port bucket. Non-Diameter traffic on 3868 (or a Version != 1) falls through to raw.
 */
export class Diameter extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Diameter.#schemaCache ??= Diameter.#buildSchema())
    }

    /** A 3-octet big-endian unsigned integer at `buffer[0..2]`. */
    static #readUInt24(buffer: Buffer): number {
        return ((buffer[0] << 16) | (buffer[1] << 8) | buffer[2]) >>> 0
    }

    /** A 3-octet big-endian buffer for `value` (only the low 24 bits are kept). */
    static #uint24ToBuffer(value: number): Buffer {
        const v: number = value >>> 0
        return Buffer.from([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])
    }

    /** Bytes available for this Diameter message: the frame end, clamped by the Message Length. During
     *  MATCH the Message Length is unset (0), so this reduces to the captured-frame bound. */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        const messageLength: number = this.instance.messageLength.getValue(0)
        if (messageLength >= 20 && messageLength < available) available = messageLength
        return available < 0 ? 0 : available
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Diameter cmd=${commandCode}',
            properties: {
                version: this.fieldUInt('version', 0, 1, 'Version'),
                messageLength: {
                    type: 'integer',
                    label: 'Message Length',
                    minimum: 0,
                    maximum: 16777215,
                    decode: function (this: Diameter): void {
                        this.instance.messageLength.setValue(Diameter.#readUInt24(this.readBytes(1, 3)))
                    },
                    encode: function (this: Diameter): void {
                        //Honor an explicitly-set Message Length (so a decoded malformed length still
                        //round-trips byte-for-byte); auto-compute only when the field is absent (crafting).
                        //The Message Length counts the whole message — the 20-byte header plus every padded
                        //AVP — which is exactly this header's final length after the AVPs have encoded.
                        const messageLength: number | undefined = this.instance.messageLength.getValue()
                        if (messageLength !== undefined && messageLength !== null) {
                            this.instance.messageLength.setValue(messageLength)
                            this.writeBytes(1, Diameter.#uint24ToBuffer(messageLength))
                        } else {
                            this.writeBytes(1, Diameter.#uint24ToBuffer(0))
                            this.addPostSelfEncodeHandler((): void => {
                                this.instance.messageLength.setValue(this.length)
                                this.writeBytes(1, Diameter.#uint24ToBuffer(this.length))
                            }, 1)
                        }
                    }
                },
                commandFlags: this.fieldUInt('commandFlags', 4, 1, 'Command Flags'),
                commandCode: {
                    type: 'integer',
                    label: 'Command Code',
                    minimum: 0,
                    maximum: 16777215,
                    decode: function (this: Diameter): void {
                        this.instance.commandCode.setValue(Diameter.#readUInt24(this.readBytes(5, 3)))
                    },
                    encode: function (this: Diameter): void {
                        const node: any = this.instance.commandCode
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
                        this.writeBytes(5, Diameter.#uint24ToBuffer(value))
                    }
                },
                applicationId: this.fieldUInt('applicationId', 8, 4, 'Application-Id'),
                hopByHopId: this.fieldUInt('hopByHopId', 12, 4, 'Hop-by-Hop Identifier'),
                endToEndId: this.fieldUInt('endToEndId', 16, 4, 'End-to-End Identifier'),
                avps: {
                    type: 'array',
                    label: 'AVPs',
                    items: {
                        type: 'object',
                        label: 'AVP',
                        properties: {
                            code: {type: 'integer', label: 'AVP Code', minimum: 0, maximum: 4294967295},
                            flags: {type: 'integer', label: 'AVP Flags', minimum: 0, maximum: 255},
                            length: {type: 'integer', label: 'AVP Length', minimum: 0, maximum: 16777215},
                            vendorId: {type: 'integer', label: 'Vendor-Id', minimum: 0, maximum: 4294967295},
                            data: {type: 'string', label: 'Data', contentEncoding: StringContentEncodingEnum.HEX},
                            padding: {type: 'string', label: 'Padding', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: Diameter): void {
                        const available: number = this.#available()
                        const avps: DiameterAVP[] = []
                        let offset: number = 20
                        //Each AVP is code(4) flags(1) length(3) [vendorId(4) if V] data padding. A Length
                        //below its own header size is invalid (and would not advance), and a Length that
                        //overruns the available bytes is truncated — in both cases stop and leave the
                        //remaining bytes to the raw layer, keeping the round-trip exact.
                        while (offset + 8 <= available) {
                            const code: number = BufferToUInt32(this.readBytes(offset, 4, true))
                            const flags: number = BufferToUInt8(this.readBytes(offset + 4, 1, true))
                            const avpLength: number = Diameter.#readUInt24(this.readBytes(offset + 5, 3, true))
                            const hasVendor: boolean = (flags & 0x80) !== 0
                            const headerSize: number = hasVendor ? 12 : 8
                            if (avpLength < headerSize || offset + avpLength > available) break
                            //Padding to the next 4-byte boundary is NOT counted in avpLength; the Message
                            //Length includes it, so it is within `available` for a well-formed message
                            //(clamped defensively for a truncated one).
                            const padLength: number = (4 - (avpLength % 4)) % 4
                            const padAvailable: number = Math.min(padLength, available - (offset + avpLength))
                            const dataLength: number = avpLength - headerSize
                            const dataOffset: number = offset + headerSize
                            const avp: DiameterAVP = {
                                code: code,
                                flags: flags,
                                length: avpLength,
                                data: dataLength > 0 ? BufferToHex(this.readBytes(dataOffset, dataLength)) : '',
                                padding: padAvailable > 0 ? BufferToHex(this.readBytes(offset + avpLength, padAvailable)) : ''
                            }
                            if (hasVendor) avp.vendorId = BufferToUInt32(this.readBytes(offset + 8, 4, true))
                            avps.push(avp)
                            offset += avpLength + padAvailable
                        }
                        this.instance.avps.setValue(avps)
                    },
                    encode: function (this: Diameter): void {
                        const avps: DiameterAVP[] = this.instance.avps.getValue([])
                        if (!avps) return
                        let offset: number = 20
                        for (const avp of avps) {
                            const flags: number = avp.flags ? avp.flags : 0
                            const hasVendor: boolean = (flags & 0x80) !== 0
                            const headerSize: number = hasVendor ? 12 : 8
                            const data: Buffer = HexToBuffer(avp.data ? avp.data : '')
                            //Honor an explicit AVP Length (a crafted AVP may lie / a decoded one carries its
                            //on-wire value); else derive it from the header size + data. For a decoded AVP
                            //these agree exactly, so the walk advances identically to decode.
                            const avpLength: number = (avp.length !== undefined && avp.length !== null)
                                ? avp.length
                                : headerSize + data.length
                            this.writeBytes(offset, UInt32ToBuffer(avp.code ? avp.code : 0))
                            this.writeBytes(offset + 4, UInt8ToBuffer(flags))
                            this.writeBytes(offset + 5, Diameter.#uint24ToBuffer(avpLength))
                            let dataOffset: number = offset + 8
                            if (hasVendor) {
                                this.writeBytes(offset + 8, UInt32ToBuffer(avp.vendorId ? avp.vendorId : 0))
                                dataOffset = offset + 12
                            }
                            if (data.length) this.writeBytes(dataOffset, data)
                            //Padding is kept verbatim so a non-zero/truncated pad round-trips; when absent
                            //(crafting) it is derived as zero bytes to the next 4-byte boundary.
                            const padding: Buffer = (avp.padding !== undefined && avp.padding !== null)
                                ? HexToBuffer(avp.padding)
                                : Buffer.alloc((4 - (avpLength % 4)) % 4, 0)
                            if (padding.length) this.writeBytes(offset + avpLength, padding)
                            offset += avpLength + padding.length
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'diameter'

    public readonly name: string = 'Diameter'

    public readonly nickname: string = 'Diameter'

    public readonly matchKeys: string[] = ['tcpport:3868']

    public match(): boolean {
        //Diameter rides on TCP port 3868 (the port bucket routes candidates here). Confirm with the
        //content signature: the full 20-byte fixed header present, Version == 1, and a plausible Message
        //Length (>= 20). During MATCH the Message Length field is unset, so #available() is the captured
        //bound only. NO heuristicFallback: this signature is too weak to claim off-port traffic.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.#available() < 20) return false
        if (BufferToUInt8(this.readBytes(0, 1, true)) !== 1) return false
        return Diameter.#readUInt24(this.readBytes(1, 3, true)) >= 20
    }

    //A leaf header — AVP values are kept as hex, not demuxed further.
    public readonly demuxProducers: DemuxProducer[] = []

}
