import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {CodecModule} from '../types/CodecModule'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * GTP-U — GPRS Tunnelling Protocol, User plane (3GPP TS 29.281), UDP port 2152. The mandatory 8-byte
 * header is a Flags byte (Version[3] / Protocol-Type / reserved / E / S / PN), a Message Type
 * (0xFF = G-PDU carries a user IP packet), a 2-byte Length (everything after the 8-byte header), and a
 * 4-byte TEID (Tunnel Endpoint Identifier). If any of E/S/PN is set, a 4-byte optional field
 * (Sequence Number + N-PDU Number + Next-Extension-Header-Type) follows, then a chain of extension
 * headers. For a G-PDU the payload after the header is a raw inner IP packet.
 *
 * The optional field + extension-header chain is kept verbatim (optionalHeader hex) so any GTP-U
 * variant round-trips byte-for-byte; the inner IP packet is left to the codec's recursion (IPv4/IPv6
 * accept a GTP-U tunnel parent, matching by IP version), decoding a fresh ip/… stack after the tunnel.
 */
export class GTPU extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (GTPU.#schemaCache ??= GTPU.#buildSchema())
    }

    static #flagBit(name: string, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'boolean',
            label: label,
            decode: function (this: GTPU): void {
                (this.instance.flags as any)[name].setValue(!!this.readBits(0, 1, bitOffset, 1))
            },
            encode: function (this: GTPU): void {
                const value: boolean = !!(this.instance.flags as any)[name].getValue()
                ;(this.instance.flags as any)[name].setValue(value)
                this.writeBits(0, 1, bitOffset, 1, value ? 1 : 0)
            }
        }
    }

    /** The payload length available for this GTP-U message, clamped by the UDP datagram. */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'GTP-U teid=${teid} type=${msgType}',
            properties: {
                //Flags byte (bit 0 = MSB): Version[0..2], PT[3], reserved[4], E[5], S[6], PN[7].
                flags: {
                    type: 'object',
                    label: 'Flags',
                    properties: {
                        version: {
                            type: 'integer',
                            label: 'Version',
                            minimum: 0,
                            maximum: 7,
                            decode: function (this: GTPU): void { this.instance.flags.version.setValue(this.readBits(0, 1, 0, 3)) },
                            encode: function (this: GTPU): void { this.writeBits(0, 1, 0, 3, this.instance.flags.version.getValue(0)) }
                        },
                        pt: this.#flagBit('pt', 3, 'Protocol Type'),
                        e: this.#flagBit('e', 5, 'Extension Header Present'),
                        s: this.#flagBit('s', 6, 'Sequence Number Present'),
                        pn: this.#flagBit('pn', 7, 'N-PDU Number Present')
                    }
                },
                msgType: this.fieldUInt('msgType', 1, 1, 'Message Type'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: GTPU): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: GTPU): void {
                        const length: number | undefined = this.instance.length.getValue()
                        if (length !== undefined && length !== null) {
                            this.instance.length.setValue(length)
                            this.writeBytes(2, UInt16ToBuffer(length))
                        } else {
                            this.writeBytes(2, UInt16ToBuffer(0))
                            //GTP-U Length = every byte after the mandatory 8-byte header (optional field +
                            //extension headers + inner payload). Compute it after the whole packet encodes.
                            this.addPostPacketEncodeHandler((): void => {
                                let started: boolean = false
                                let total: number = 0
                                this.codecModules.forEach((codecModule: CodecModule): void => {
                                    if (codecModule === this) started = true
                                    if (started) total += codecModule.length
                                })
                                const value: number = total - 8 < 0 ? 0 : total - 8
                                this.instance.length.setValue(value)
                                this.writeBytes(2, UInt16ToBuffer(value))
                            }, 1)
                        }
                    }
                },
                teid: this.fieldHex('teid', 4, 4, 'TEID'),
                //Optional field (Sequence Number + N-PDU Number + Next Extension Header Type) and any
                //extension-header chain, kept verbatim. Empty when E/S/PN are all clear.
                optionalHeader: {
                    type: 'string',
                    label: 'Optional Header',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    hidden: true,
                    decode: function (this: GTPU): void {
                        const e: boolean = !!this.instance.flags.e.getValue()
                        const s: boolean = !!this.instance.flags.s.getValue()
                        const pn: boolean = !!this.instance.flags.pn.getValue()
                        if (!e && !s && !pn) {
                            this.instance.optionalHeader.setValue('')
                            return
                        }
                        const available: number = this.#available()
                        //4 optional bytes: Sequence Number(2) + N-PDU Number(1) + Next-Ext-Header-Type(1).
                        let optionalLength: number = 4
                        if (e) {
                            //Walk the extension-header chain: each is length(1, in 4-octet units) + body +
                            //a trailing Next-Extension-Header-Type; a 0 type ends the chain.
                            let nextType: number = BufferToUInt8(this.readBytes(11, 1, true))
                            let offset: number = 12
                            let guard: number = 0
                            while (nextType !== 0 && offset < available && guard++ < 256) {
                                const units: number = BufferToUInt8(this.readBytes(offset, 1, true))
                                if (units === 0) break
                                const extBytes: number = units * 4
                                if (offset + extBytes > available) break
                                nextType = BufferToUInt8(this.readBytes(offset + extBytes - 1, 1, true))
                                offset += extBytes
                            }
                            optionalLength = offset - 8
                        }
                        if (8 + optionalLength > available) optionalLength = available - 8
                        this.instance.optionalHeader.setValue(optionalLength > 0 ? BufferToHex(this.readBytes(8, optionalLength)) : '')
                    },
                    encode: function (this: GTPU): void {
                        const optionalHeader: string = this.instance.optionalHeader.getValue('')
                        if (optionalHeader) this.writeBytes(8, HexToBuffer(optionalHeader))
                    }
                },
                //Non-G-PDU messages (message type != 0xFF: Echo, Error Indication, End Marker, …) carry
                //GTP Information Elements, NOT an inner IP packet. Consume them here so the codec's
                //recursion has nothing left to (mis)interpret as inner IP by the version nibble. For a
                //G-PDU (0xFF) this is empty and the header stops after the optional field, leaving the
                //inner IP packet to be decoded recursively.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    hidden: true,
                    decode: function (this: GTPU): void {
                        const msgType: number = this.instance.msgType.getValue(0)
                        if (msgType === 0xff) {
                            this.instance.payload.setValue('')
                            return
                        }
                        const available: number = this.#available()
                        const consumed: number = 8 + HexToBuffer(this.instance.optionalHeader.getValue('')).length
                        this.instance.payload.setValue(consumed < available ? BufferToHex(this.readBytes(consumed, available - consumed)) : '')
                    },
                    encode: function (this: GTPU): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) {
                            const consumed: number = 8 + HexToBuffer(this.instance.optionalHeader.getValue('')).length
                            this.writeBytes(consumed, HexToBuffer(payload))
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'gtp'

    public readonly name: string = 'GPRS Tunnelling Protocol, User plane'

    public readonly nickname: string = 'GTP-U'

    public readonly matchKeys: string[] = ['udpport:2152']

    public match(): boolean {
        //Require the 8-byte mandatory header within the UDP payload (see RADIUS: bound by payload).
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp' && this.#available() >= 8
    }

    //No child demux key; the inner IP packet is matched by IPv4/IPv6's tunnel-aware match() (which
    //accepts a 'gtp' parent and matches by the IP version nibble), so recursion decodes the inner stack.
    public readonly demuxProducers: DemuxProducer[] = []

}
