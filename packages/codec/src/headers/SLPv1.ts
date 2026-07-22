import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * SLPv1 — Service Location Protocol Version 1 (RFC 2165), UDP (and TCP) port 427. An SLPv1 message
 * begins with a 12-octet common header: an 8-bit Version (1), an 8-bit Function (1 SrvReq, 2 SrvRply,
 * 3 SrvReg, 4 SrvDeReg, 5 SrvAck, 6 AttrRqst, 7 AttrRply, 8 DAAdvert, 9 SrvTypeRqst, 10 SrvTypeRply),
 * a 16-bit Length (the whole message octet count including this header), an 8-bit Flags field (bit 0
 * Overflow, bit 1 Monolingual, bit 2 URL Authentication, bit 3 Attribute Authentication, bit 4 Fresh;
 * the remaining 3 bits reserved), an 8-bit Dialect, a 2-octet Language Code (ISO 639, e.g. "en"), a
 * 16-bit Character Encoding (MIBenum) and a 16-bit XID — then the Function-specific body.
 *
 * The body layout differs per Function and several sub-structures carry authentication blocks and
 * cross-message context, so this common-header codec keeps the body verbatim as `body` hex (byte-
 * perfect) and does not sub-decode it. The Length is auto-computed on encode when not supplied, else
 * honored verbatim (a crafted message may lie). The message is bounded by its Length (and the UDP
 * datagram) so trailing / pipelined bytes are left to the codec's recursion / RawData. A well-formed
 * message round-trips byte-for-byte.
 *
 * Note: SLPv1 (RFC 2165) and SLPv2 (RFC 2608, see SLP) share port 427 but have entirely different
 * header layouts, so they are separate codecs selected by the Version octet (1 vs 2).
 */
export class SLPv1 extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SLPv1.#schemaCache ??= SLPv1.#buildSchema())
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

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SLPv1 func=${functionId} xid=${xid}',
            properties: {
                version: this.fieldUInt('version', 0, 1, 'Version'),
                functionId: this.fieldUInt('functionId', 1, 1, 'Function'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: SLPv1): void {
                        const b: Buffer = this.readBytes(2, 2)
                        this.instance.length.setValue((b[0] << 8) | b[1])
                    },
                    encode: function (this: SLPv1): void {
                        //Length counts the whole message = 12-byte common header + body. Honored when
                        //supplied (a crafted message may lie); else derived from the body bytes.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 12 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) value = 0
                        this.instance.length.setValue(value)
                        this.writeBytes(2, Buffer.from([(value >> 8) & 0xff, value & 0xff]))
                    }
                },
                //Flags: bit 0 Overflow, bit 1 Monolingual, bit 2 URL Auth, bit 3 Attr Auth, bit 4 Fresh;
                //the remaining 3 bits reserved. Kept as a plain uint8 so reserved bits round-trip.
                flags: this.fieldUInt('flags', 4, 1, 'Flags'),
                dialect: this.fieldUInt('dialect', 5, 1, 'Dialect'),
                //2-octet ISO 639 Language Code (e.g. "en"), kept verbatim as hex so any value round-trips.
                languageCode: {
                    type: 'string',
                    label: 'Language Code',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SLPv1): void {
                        this.instance.languageCode.setValue(BufferToHex(this.readBytes(6, 2)))
                    },
                    encode: function (this: SLPv1): void {
                        const code: string = this.instance.languageCode.getValue('')
                        this.writeBytes(6, code ? HexToBuffer(code) : Buffer.alloc(2, 0))
                    }
                },
                charEncoding: this.fieldUInt('charEncoding', 8, 2, 'Character Encoding'),
                xid: this.fieldUInt('xid', 10, 2, 'XID'),
                //The Function-specific body after the 12-byte common header, kept verbatim. Bounded by the
                //message Length and the captured / UDP bytes, so trailing / pipelined data is left to the
                //codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SLPv1): void {
                        const available: number = this.#boundedAvailable()
                        let end: number = this.instance.length.getValue(0)
                        if (end > available) end = available
                        this.instance.body.setValue(end > 12 ? BufferToHex(this.readBytes(12, end - 12)) : '')
                    },
                    encode: function (this: SLPv1): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(12, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'slpv1'

    public readonly name: string = 'Service Location Protocol Version 1'

    public readonly nickname: string = 'SLPv1'

    public readonly matchKeys: string[] = ['udpport:427', 'tcpport:427']

    public match(): boolean {
        //SLPv1 rides on UDP/TCP port 427 (shared with SLPv2). Require the full 12-byte common header and
        //Version == 1 (the SLPv1 content signature) so non-SLP 427 traffic falls through to raw.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'udp' && this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 12) return false
        return this.readBytes(0, 1, true)[0] === 1
    }

    //A leaf header — the Function-specific body requires per-type, cross-message parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
