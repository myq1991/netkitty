import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * CAPWAP — Control And Provisioning of Wireless Access Points (RFC 5415), UDP port 5246 (control) and
 * 5247 (data). Every CAPWAP message begins with a fixed 8-byte header whose layout is a preamble octet
 * followed by tightly bit-packed fields:
 *
 *   - Preamble (octet 0): Version (high nibble) + Type (low nibble). Type 0 = a CAPWAP header follows,
 *     Type 1 = the payload is a DTLS record (the header below is then not present).
 *   - Octets 1-3 (24 bits): HLEN (5 bits, the whole CAPWAP header length in units of 4 octets),
 *     RID (5 bits, Radio ID), WBID (5 bits, Wireless Binding ID), then the flag bits T, F, L, W, M, K
 *     (1 bit each) and a 3-bit reserved Flags remainder.
 *   - Octets 4-5: Fragment ID (16 bits).
 *   - Octets 6-7: Fragment Offset (13 bits) + a 3-bit reserved field.
 *
 * When the M/W flags are set the header carries optional Radio MAC Address / Wireless Specific
 * Information fields; HLEN delimits the whole header (HLEN × 4 octets), after which the payload begins
 * (the control-plane Control Header + message elements, or the tunneled 802.3/802.11 data frame).
 *
 * This is the minimal, byte-faithful slice: the preamble and every bit-packed field are modelled so an
 * editor can see/round-trip them, the optional per-flag header fields are kept verbatim as
 * `headerRemainder` hex (bounded by HLEN × 4), and everything after the header is kept verbatim as
 * `payload` hex (bounded by the UDP datagram so a retained trailer is not absorbed). Sub-decoding the
 * Control Header / message elements or the tunneled frame is deferred, so CAPWAP is effectively a leaf.
 * HLEN is honored verbatim when supplied (a crafted header may lie) else derived from the header bytes;
 * a well-formed message round-trips byte-for-byte.
 */
export class CAPWAP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (CAPWAP.#schemaCache ??= CAPWAP.#buildSchema())
    }

    /** The payload length bounded by the UDP datagram (so a retained trailer/padding is not absorbed). */
    #payloadBound(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /** A single flag bit within the 24-bit field packed across octets 1-3 (bit 0 = MSB of octet 1). */
    static #flagBit(name: string, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'boolean',
            label: label,
            decode: function (this: CAPWAP): void {
                (this.instance.flags as any)[name].setValue(!!this.readBits(1, 3, bitOffset, 1))
            },
            encode: function (this: CAPWAP): void {
                const value: boolean = !!(this.instance.flags as any)[name].getValue()
                ;(this.instance.flags as any)[name].setValue(value)
                this.writeBits(1, 3, bitOffset, 1, value ? 1 : 0)
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'CAPWAP v${version} type=${type} hlen=${hlen}',
            properties: {
                //Preamble (octet 0): Version (high nibble) + Type (low nibble, 0 = CAPWAP header, 1 = DTLS).
                version: {
                    type: 'integer',
                    label: 'Version',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: CAPWAP): void {
                        this.instance.version.setValue(this.readBits(0, 1, 0, 4))
                    },
                    encode: function (this: CAPWAP): void {
                        this.writeBits(0, 1, 0, 4, this.instance.version.getValue(0))
                    }
                },
                type: {
                    type: 'integer',
                    label: 'Type',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: CAPWAP): void {
                        this.instance.type.setValue(this.readBits(0, 1, 4, 4))
                    },
                    encode: function (this: CAPWAP): void {
                        this.writeBits(0, 1, 4, 4, this.instance.type.getValue(0))
                    }
                },
                //HLEN (octet 1-3 bits 0-4): the whole CAPWAP header length in units of 4 octets. Honored
                //verbatim when supplied (a crafted header may lie); else derived from the 8-byte fixed
                //header plus the verbatim optional (headerRemainder) bytes. HLEN × 4 delimits the header.
                hlen: {
                    type: 'integer',
                    label: 'HLEN',
                    minimum: 0,
                    maximum: 31,
                    decode: function (this: CAPWAP): void {
                        this.instance.hlen.setValue(this.readBits(1, 3, 0, 5))
                    },
                    encode: function (this: CAPWAP): void {
                        const provided: number | undefined = this.instance.hlen.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : Math.ceil((8 + HexToBuffer(this.instance.headerRemainder.getValue('')).length) / 4)
                        if (value > 31) {
                            this.recordError(this.instance.hlen.getPath(), 'Maximum value is 31')
                            value = 31
                        }
                        if (value < 0) {
                            this.recordError(this.instance.hlen.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.hlen.setValue(value)
                        this.writeBits(1, 3, 0, 5, value)
                    }
                },
                //RID (octet 1-3 bits 5-9): Radio ID.
                rid: {
                    type: 'integer',
                    label: 'RID',
                    minimum: 0,
                    maximum: 31,
                    decode: function (this: CAPWAP): void {
                        this.instance.rid.setValue(this.readBits(1, 3, 5, 5))
                    },
                    encode: function (this: CAPWAP): void {
                        this.writeBits(1, 3, 5, 5, this.instance.rid.getValue(0))
                    }
                },
                //WBID (octet 1-3 bits 10-14): Wireless Binding ID (1 = IEEE 802.11).
                wbid: {
                    type: 'integer',
                    label: 'WBID',
                    minimum: 0,
                    maximum: 31,
                    decode: function (this: CAPWAP): void {
                        this.instance.wbid.setValue(this.readBits(1, 3, 10, 5))
                    },
                    encode: function (this: CAPWAP): void {
                        this.writeBits(1, 3, 10, 5, this.instance.wbid.getValue(0))
                    }
                },
                //Flag bits (octet 1-3 bits 15-20): T (payload type), F (fragment), L (last fragment),
                //W (Wireless Specific Info present), M (Radio MAC present), K (keep-alive).
                flags: {
                    type: 'object',
                    label: 'Flags',
                    properties: {
                        t: this.#flagBit('t', 15, 'T (Payload Type)'),
                        f: this.#flagBit('f', 16, 'F (Fragment)'),
                        l: this.#flagBit('l', 17, 'L (Last Fragment)'),
                        w: this.#flagBit('w', 18, 'W (Wireless Specific Info)'),
                        m: this.#flagBit('m', 19, 'M (Radio MAC Present)'),
                        k: this.#flagBit('k', 20, 'K (Keep-Alive)')
                    }
                },
                //Flags reserved remainder (octet 1-3 bits 21-23). RFC 5415 requires 0, kept verbatim.
                flagsReserved: {
                    type: 'integer',
                    label: 'Flags Reserved',
                    minimum: 0,
                    maximum: 7,
                    hidden: true,
                    decode: function (this: CAPWAP): void {
                        this.instance.flagsReserved.setValue(this.readBits(1, 3, 21, 3))
                    },
                    encode: function (this: CAPWAP): void {
                        this.writeBits(1, 3, 21, 3, this.instance.flagsReserved.getValue(0))
                    }
                },
                //Fragment ID (octet 4-5): identifies fragments of a single CAPWAP message.
                fragmentId: this.fieldUInt('fragmentId', 4, 2, 'Fragment ID'),
                //Fragment Offset (octet 6-7 bits 0-12): the fragment's offset in units of 8 octets.
                fragmentOffset: {
                    type: 'integer',
                    label: 'Fragment Offset',
                    minimum: 0,
                    maximum: 8191,
                    decode: function (this: CAPWAP): void {
                        this.instance.fragmentOffset.setValue(this.readBits(6, 2, 0, 13))
                    },
                    encode: function (this: CAPWAP): void {
                        this.writeBits(6, 2, 0, 13, this.instance.fragmentOffset.getValue(0))
                    }
                },
                //Reserved (octet 6-7 bits 13-15). RFC 5415 requires 0, kept verbatim.
                reserved: {
                    type: 'integer',
                    label: 'Reserved',
                    minimum: 0,
                    maximum: 7,
                    hidden: true,
                    decode: function (this: CAPWAP): void {
                        this.instance.reserved.setValue(this.readBits(6, 2, 13, 3))
                    },
                    encode: function (this: CAPWAP): void {
                        this.writeBits(6, 2, 13, 3, this.instance.reserved.getValue(0))
                    }
                },
                //The optional per-flag header fields (Radio MAC Address / Wireless Specific Information),
                //kept verbatim and bounded by HLEN × 4. Empty for the minimal 8-byte header (HLEN = 2).
                headerRemainder: {
                    type: 'string',
                    label: 'Header Remainder',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: CAPWAP): void {
                        const hlen: number = this.instance.hlen.getValue(0)
                        const available: number = this.packet.length - this.startPos
                        let headerEnd: number = hlen * 4
                        if (headerEnd < 8) headerEnd = 8
                        if (headerEnd > available) headerEnd = available
                        this.instance.headerRemainder.setValue(headerEnd > 8 ? BufferToHex(this.readBytes(8, headerEnd - 8)) : '')
                    },
                    encode: function (this: CAPWAP): void {
                        const headerRemainder: string = this.instance.headerRemainder.getValue('')
                        if (headerRemainder) this.writeBytes(8, HexToBuffer(headerRemainder))
                    }
                },
                //Everything after the CAPWAP header (Control Header + message elements, or the tunneled
                //802.3/802.11 data frame), kept verbatim. Bounded by the UDP datagram so a retained
                //trailer is not absorbed; sub-decoding is deferred (CAPWAP is effectively a leaf here).
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: CAPWAP): void {
                        const hlen: number = this.instance.hlen.getValue(0)
                        let headerEnd: number = hlen * 4
                        if (headerEnd < 8) headerEnd = 8
                        const end: number = this.#payloadBound()
                        if (headerEnd > end) headerEnd = end
                        this.instance.payload.setValue(end > headerEnd ? BufferToHex(this.readBytes(headerEnd, end - headerEnd)) : '')
                    },
                    encode: function (this: CAPWAP): void {
                        const hlen: number = this.instance.hlen.getValue(0)
                        let headerEnd: number = hlen * 4
                        if (headerEnd < 8) headerEnd = 8
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(headerEnd, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'capwap'

    public readonly name: string = 'Control And Provisioning of Wireless Access Points'

    public readonly nickname: string = 'CAPWAP'

    //Well-known UDP ports 5246 (control) and 5247 (data). No content magic, so selection is
    //port-bucketed only (no heuristicFallback).
    public readonly matchKeys: string[] = ['udpport:5246', 'udpport:5247']

    public match(): boolean {
        //Require the fixed 8-byte header within the UDP payload (not just the captured frame — a padded
        //sub-8-byte datagram on a CAPWAP port would otherwise over-read the trailer into the header).
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        return this.#payloadBound() >= 8
    }

    //A leaf header — the Control Header / message elements and the tunneled frame are kept verbatim.
    public readonly demuxProducers: DemuxProducer[] = []

}
