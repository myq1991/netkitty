import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * WCCP v2 — Web Cache Communication Protocol version 2 (Cisco, draft-wilson-wrec-wccp-v2), carried over
 * UDP port 2048. Every WCCP v2 message begins with a fixed 8-byte header — a 4-byte message Type
 * (0x0000000A Here-I-Am, 0x0000000B I-See-You, 0x0000000C Redirect-Assign, 0x0000000D Removal-Query),
 * a 2-byte Version (0x0200 for WCCP v2) and a 2-byte Length (the octet count of the component data that
 * follows the header, NOT including these 8 bytes) — followed by a sequence of component TLVs (each a
 * 2-byte component Type, a 2-byte component Length, and a value).
 *
 * The component layout differs per message type and per component (Security Info, Service Info,
 * Web-Cache/Router Identity, Assignment, Capabilities, Command Extension) and several sub-structures
 * need cross-message context, so this codec keeps the component region verbatim as `components` hex
 * (byte-perfect) and does not sub-decode it. The Length is honored when supplied (a crafted message may
 * lie) and derived from the component bytes only when absent; the message is bounded by BOTH Length and
 * the UDP payload so a trailing datagram / padding is left to the codec's recursion / RawData. A
 * well-formed message round-trips byte-for-byte. This is a leaf header — nothing demuxes off WCCP.
 */
export class WCCP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (WCCP.#schemaCache ??= WCCP.#buildSchema())
    }

    /** Bytes available for this WCCP message: the frame end, clamped by the UDP payload length. */
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
            summary: 'WCCP type=${type} len=${length}',
            properties: {
                type: this.fieldUInt('type', 0, 4, 'Type'),
                version: this.fieldUInt('version', 4, 2, 'Version'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: WCCP): void {
                        this.instance.length.setValue(this.readBytes(6, 2).readUInt16BE(0))
                    },
                    encode: function (this: WCCP): void {
                        //Length counts only the component data after the 8-byte header. Honored when
                        //supplied (a crafted message may lie); else derived from the component bytes.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.components.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(6, UInt16ToBuffer(value))
                    }
                },
                //The component TLV region after the 8-byte header, kept verbatim. Bounded by BOTH the
                //message Length (the message ends at 8 + Length) and the UDP payload, so trailing /
                //pipelined data is left to the codec's recursion / RawData.
                components: {
                    type: 'string',
                    label: 'Components',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: WCCP): void {
                        const available: number = this.#available()
                        const length: number = this.instance.length.getValue(0)
                        let end: number = 8 + length
                        if (end > available) end = available
                        this.instance.components.setValue(end > 8 ? BufferToHex(this.readBytes(8, end - 8)) : '')
                    },
                    encode: function (this: WCCP): void {
                        const components: string = this.instance.components.getValue('')
                        if (components) this.writeBytes(8, HexToBuffer(components))
                    }
                }
            }
        }
    }

    public readonly id: string = 'wccp'

    public readonly name: string = 'Web Cache Communication Protocol'

    public readonly nickname: string = 'WCCP'

    //Port-defined (udp:2048). WCCP v2 does carry a content signature (Version = 0x0200), but that alone
    //is weak, so it stays a plain bucket entry (no heuristicFallback): WCCP only when it rides UDP/2048.
    public readonly matchKeys: string[] = ['udpport:2048']

    public match(): boolean {
        //WCCP rides on UDP port 2048. Require the full 8-byte header within the UDP payload (bounded by
        //udp.length, not the whole frame remainder, so Ethernet padding is not mis-claimed).
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        return this.#available() >= 8
    }

    //A leaf header — the component TLVs require per-type, cross-message parsing and are kept verbatim.
    public readonly demuxProducers: DemuxProducer[] = []

}
