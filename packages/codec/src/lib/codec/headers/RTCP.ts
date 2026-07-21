import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * RTCP — RTP Control Protocol (RFC 3550 §6), the companion control channel to RTP. Rides UDP on
 * dynamically negotiated ports (classically the RTP media port + 1, or multiplexed onto the media port
 * with rtcp-mux, RFC 5761), so there is no fixed well-known port; a small set of common defaults is
 * declared as matchKeys and selection stays strictly port-bucketed (see match()).
 *
 * Every RTCP packet begins with a 4-byte common header — Version (2 bits, always 2), Padding (1 bit),
 * a 5-bit count whose meaning is packet-type-specific (Reception Report Count for SR/RR, Source Count
 * for SDES/BYE), an 8-bit Packet Type (200 SR, 201 RR, 202 SDES, 203 BYE, 204 APP, 205 RTPFB, 206
 * PSFB, 207 XR) and a 16-bit Length in 32-bit words minus one (RFC 3550 §6.4.1) — and, for the
 * report-bearing types, an SSRC of the sender. RTCP packets are transmitted as COMPOUND packets:
 * several stacked back-to-back in a single UDP datagram (RFC 3550 §6.1).
 *
 * This minimal codec structures the FIRST packet's common header (version/padding/count/packetType/
 * length) plus its SSRC, then keeps that first packet's remaining body verbatim as `body` hex (bounded
 * by the Length field — packet-type-specific decoding of SR sender info / report blocks / SDES chunks
 * is a later enrichment), and keeps any further compound packets verbatim as `rest` hex (bounded by
 * the UDP payload). The Length is honored when supplied (a crafted packet may lie) else derived from
 * the body; every field is width-clamped so a decoded value always re-encodes. A well-formed datagram
 * round-trips byte-for-byte.
 */
export class RTCP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (RTCP.#schemaCache ??= RTCP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'RTCP pt=${packetType} len=${length}',
            properties: {
                //Byte 0 packs Version (bits 0-1), Padding (bit 2) and a 5-bit count (bits 3-7). Each is a
                //separate field over the same octet window; writeBits read-modify-writes so sequential
                //encode of the three composes byte 0 correctly.
                version: {
                    type: 'integer',
                    label: 'Version',
                    minimum: 0,
                    maximum: 3,
                    decode: function (this: RTCP): void {
                        this.instance.version.setValue(this.readBits(0, 1, 0, 2))
                    },
                    encode: function (this: RTCP): void {
                        const node: any = this.instance.version
                        let value: number = node.getValue(2, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 3) value = 3
                        if (value < 0) value = 0
                        node.setValue(value)
                        this.writeBits(0, 1, 0, 2, value)
                    }
                },
                //Padding flag: when set, the packet ends with padding octets whose last byte is the pad
                //count (RFC 3550 §6.4.1). The padding bytes themselves live inside `body`/`rest` verbatim.
                padding: {
                    type: 'integer',
                    label: 'Padding',
                    minimum: 0,
                    maximum: 1,
                    decode: function (this: RTCP): void {
                        this.instance.padding.setValue(this.readBits(0, 1, 2, 1))
                    },
                    encode: function (this: RTCP): void {
                        const node: any = this.instance.padding
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 1) value = 1
                        if (value < 0) value = 0
                        node.setValue(value)
                        this.writeBits(0, 1, 2, 1, value)
                    }
                },
                //5-bit count: Reception Report Count (SR/RR) or Source Count (SDES/BYE), packet-type
                //dependent. Kept as a plain integer; its per-type semantics are UI enrichment for later.
                reportCount: {
                    type: 'integer',
                    label: 'Report/Source Count',
                    minimum: 0,
                    maximum: 31,
                    decode: function (this: RTCP): void {
                        this.instance.reportCount.setValue(this.readBits(0, 1, 3, 5))
                    },
                    encode: function (this: RTCP): void {
                        const node: any = this.instance.reportCount
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 31) value = 31
                        if (value < 0) value = 0
                        node.setValue(value)
                        this.writeBits(0, 1, 3, 5, value)
                    }
                },
                //Packet Type (200 SR .. 207 XR). A plain uint8 — no hard enum, so an unknown/future type
                //still decodes and re-encodes (never-throws).
                packetType: this.fieldUInt('packetType', 1, 1, 'Packet Type'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: RTCP): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: RTCP): void {
                        //Length = 32-bit words of the first packet minus one (RFC 3550 §6.4.1). The first
                        //packet is the 8-byte header+SSRC plus `body`. Honored when supplied (a crafted
                        //packet may lie); else derived from the body length.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : Math.floor((8 + HexToBuffer(this.instance.body.getValue('')).length) / 4) - 1
                        if (value < 0) value = 0
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(2, UInt16ToBuffer(value))
                    }
                },
                //SSRC of the sender (SR/RR/report-bearing types). Kept verbatim as hex — an identifier the
                //editor round-trips untouched, no endian ambiguity.
                ssrc: this.fieldHex('ssrc', 4, 4, 'SSRC'),
                //The first RTCP packet's remaining body after the 8-byte header+SSRC: SR sender info,
                //report blocks, SDES chunks, etc. Bounded by the Length field (the first packet ends at
                //(Length+1)*4 bytes) and the captured bytes, so trailing compound packets are NOT swallowed.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: RTCP): void {
                        const available: number = this.packet.length - this.startPos
                        let firstEnd: number = (this.instance.length.getValue(0) + 1) * 4
                        if (firstEnd < 8) firstEnd = 8
                        if (firstEnd > available) firstEnd = available
                        this.instance.body.setValue(firstEnd > 8 ? BufferToHex(this.readBytes(8, firstEnd - 8)) : '')
                    },
                    encode: function (this: RTCP): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(8, HexToBuffer(body))
                    }
                },
                //Any further packets in the compound RTCP datagram (RFC 3550 §6.1), kept verbatim. Starts
                //where the first packet ends ((Length+1)*4) and runs to the end of the UDP payload; a leaf
                //field, sub-decoding each stacked packet is a later enrichment.
                rest: {
                    type: 'string',
                    label: 'Compound Remainder',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: RTCP): void {
                        const available: number = this.packet.length - this.startPos
                        let firstEnd: number = (this.instance.length.getValue(0) + 1) * 4
                        if (firstEnd < 8) firstEnd = 8
                        if (firstEnd > available) firstEnd = available
                        this.instance.rest.setValue(available > firstEnd ? BufferToHex(this.readBytes(firstEnd, available - firstEnd)) : '')
                    },
                    encode: function (this: RTCP): void {
                        const rest: string = this.instance.rest.getValue('')
                        if (!rest) return
                        let firstEnd: number = (this.instance.length.getValue(0) + 1) * 4
                        if (firstEnd < 8) firstEnd = 8
                        this.writeBytes(firstEnd, HexToBuffer(rest))
                    }
                }
            }
        }
    }

    public readonly id: string = 'rtcp'

    public readonly name: string = 'RTP Control Protocol'

    public readonly nickname: string = 'RTCP'

    //RTCP uses dynamically negotiated UDP ports with no fixed well-known port. Like RTP, the common
    //defaults are declared as port buckets and selection stays STRICTLY port-bucketed — heuristicFallback
    //is deliberately NOT set, because Version==2 + a Packet Type in 200-207 is a weak signature that
    //would falsely claim unrelated UDP traffic if run over every datagram. Recognition on other ports is
    //a "decode as" concern, mirroring RTP.
    public readonly matchKeys: string[] = ['udpport:5005', 'udpport:5007', 'udpport:5009']

    public match(): boolean {
        //Only ever consulted for the declared UDP port buckets (no heuristic fallback). Within a bucket,
        //guard on the two-bit Version (must be 2) and a Packet Type in the RTCP range 200-207 (RFC 3550,
        //RFC 4585/4587) so non-RTCP traffic on these ports falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.packet.length - this.startPos < 8) return false
        const version: number = (this.readBytes(0, 1, true)[0] >> 6) & 0x03
        if (version !== 2) return false
        const packetType: number = this.readBytes(1, 1, true)[0]
        return packetType >= 200 && packetType <= 207
    }

    //A leaf header — packet-type-specific body and stacked compound packets are kept verbatim.
    public readonly demuxProducers: DemuxProducer[] = []

}
