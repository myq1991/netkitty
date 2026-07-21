import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt16} from '../helper/BufferToNumber'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * PPPoE Session Stage (RFC 2516), carried directly in an Ethernet II frame with EtherType 0x8864 (an
 * Ethernet child — no IP/UDP). The 6-byte PPPoE header is a byte holding Version (high 4 bits, 1) and
 * Type (low 4 bits, 1), a 1-byte Code (0x00 in the Session Stage), a 2-byte Session ID (non-zero), and
 * a 2-byte Length (the octet count of the PPPoE payload — i.e. the PPP portion, which starts with the
 * 2-byte PPP Protocol field). The payload follows: a 2-byte PPP Protocol (e.g. 0x0021 IPv4, 0x0057
 * IPv6, 0xc021 LCP, 0x8021 IPCP) and its data.
 *
 * This minimal slice decodes the 6-byte header plus the 2-byte PPP Protocol and keeps the PPP data
 * verbatim as `payload` hex (byte-perfect), bounded by the Length field so trailing Ethernet padding is
 * left to the codec's recursion / RawData. The Length is honored verbatim when supplied (a crafted
 * frame may lie) else derived from the actual payload (2-byte Protocol + data). A well-formed frame
 * round-trips byte-for-byte. Inner IPv4/IPv6/LCP recursion is deferred to a serial follow-up (it needs
 * a pppProtocol-driven demux into IPv4/IPv6.match); for now the PPP payload is a bounded-hex leaf.
 */
export class PPPoESession extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (PPPoESession.#schemaCache ??= PPPoESession.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'PPPoE Session id=${sessionId} proto=${pppProtocol}',
            properties: {
                //Byte 0: Version in the high 4 bits, Type in the low 4 bits (both 1 in RFC 2516). Split
                //into two nibble fields so the editor sees them, kept verbatim for byte-perfect.
                version: {
                    type: 'integer', label: 'Version', minimum: 0, maximum: 15,
                    decode: function (this: PPPoESession): void { this.instance.version.setValue(this.readBits(0, 1, 0, 4)) },
                    encode: function (this: PPPoESession): void { this.writeBits(0, 1, 0, 4, this.instance.version.getValue(0)) }
                },
                type: {
                    type: 'integer', label: 'Type', minimum: 0, maximum: 15,
                    decode: function (this: PPPoESession): void { this.instance.type.setValue(this.readBits(0, 1, 4, 4)) },
                    encode: function (this: PPPoESession): void { this.writeBits(0, 1, 4, 4, this.instance.type.getValue(0)) }
                },
                //Code — 0x00 in the Session Stage (Discovery Stage codes live in a separate header).
                code: this.fieldUInt('code', 1, 1, 'Code'),
                //Session ID — assigned during Discovery; non-zero for an established session.
                sessionId: this.fieldUInt('sessionId', 2, 2, 'Session ID'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: PPPoESession): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(4, 2)))
                    },
                    encode: function (this: PPPoESession): void {
                        //Length counts the PPPoE payload = 2-byte PPP Protocol + data. Honored when
                        //supplied (a crafted frame may lie); else derived from the actual payload.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 2 + HexToBuffer(this.instance.payload.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(4, UInt16ToBuffer(value))
                    }
                },
                //The 2-byte PPP Protocol at the start of the payload (offset 6), kept as a lowercase hex
                //string. A serial follow-up will make this a demux producer into the inner IPv4/IPv6/LCP.
                pppProtocol: this.fieldHex('pppProtocol', 6, 2, 'PPP Protocol'),
                //The PPP data after the Protocol field (offset 8), kept verbatim. Bounded by the Length
                //field (payload ends at header offset 6 + Length) and the captured bytes, so trailing
                //Ethernet padding / pipelined data is left to the codec's recursion / RawData.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: PPPoESession): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        let end: number = 6 + length
                        if (end > remaining) end = remaining
                        this.instance.payload.setValue(end > 8 ? BufferToHex(this.readBytes(8, end - 8)) : '')
                    },
                    encode: function (this: PPPoESession): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(8, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'pppoe-sess'

    public readonly name: string = 'PPP-over-Ethernet Session'

    public readonly nickname: string = 'PPPoE Session'

    public readonly matchKeys: string[] = ['ethertype:8864']

    public match(): boolean {
        //An Ethernet (or VLAN) child selected by EtherType 0x8864 (stored as a lowercase 4-hex string).
        //Require the 6-byte PPPoE header minimum.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.instance.etherType.getValue() !== '8864') return false
        return this.packet.length - this.startPos >= 6
    }

    //A leaf header for this slice — the inner PPP payload (IPv4/IPv6/LCP) is deferred to a serial
    //follow-up that will add a pppProtocol-driven demux; for now it is kept as bounded-hex `payload`.
    public readonly demuxProducers: DemuxProducer[] = []

}
