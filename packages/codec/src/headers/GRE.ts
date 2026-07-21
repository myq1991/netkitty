import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt16, BufferToUInt32} from '../helper/BufferToNumber'
import {UInt16ToBuffer, UInt32ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * GRE — Generic Routing Encapsulation (RFC 2784 + key/sequence extensions RFC 2890), carried directly
 * over IP as protocol 47. The 4-byte base header is a flags/version field — C (Checksum Present), the
 * legacy R (Routing) bit, K (Key Present), S (Sequence Number Present), the legacy s/Recur bits, a
 * reserved field, and a 3-bit Version (0 for GRE) — followed by a 16-bit Protocol Type (the EtherType
 * of the payload). Optional trailing fields follow in order: a Checksum + Reserved1 (4 bytes, if C), a
 * Key (4 bytes, if K), and a Sequence Number (4 bytes, if S). The inner frame follows.
 *
 * Like GENEVE, the inner frame is dispatched by Protocol Type: an ethertype demux producer routes an
 * inner IPv4/IPv6 packet (0x0800/0x86dd) to IPv4/IPv6 (which accept a 'gre' parent), while a Transparent
 * Ethernet Bridging payload (0x6558) falls through to EthernetII (guarded to that type). The GRE
 * checksum is honored verbatim, not recomputed (encode is a faithful executor); a well-formed GRE
 * message round-trips byte-for-byte. The legacy Routing (R=1, RFC 1701) fields are not parsed.
 */
export class GRE extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (GRE.#schemaCache ??= GRE.#buildSchema())
    }

    /**
     * The length available to GRE's own header (base + optional fields), bounded by the enclosing IP
     * datagram — so a lying flag near the end of the IP payload does not read into a trailing FCS. This
     * bounds GRE's field reads and the match gate; the inner frame is left to the codec's recursion
     * (which, like the other tunnels, reads to the end of the captured packet).
     */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'ipv4') {
            const ipPayload: number = prev.instance.length.getValue(0) - prev.length
            if (ipPayload >= 0 && ipPayload < available) available = ipPayload
        } else if (prev && prev.id === 'ipv6') {
            const ipPayload: number = prev.instance.plen.getValue(0)
            if (ipPayload >= 0 && ipPayload < available) available = ipPayload
        }
        return available < 0 ? 0 : available
    }

    /** A single flag bit within the 2-byte flags/version field (bit 0 = MSB of byte 0). */
    static #flagBit(name: string, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'boolean',
            label: label,
            decode: function (this: GRE): void {
                (this.instance.flags as any)[name].setValue(!!this.readBits(0, 1, bitOffset, 1))
            },
            encode: function (this: GRE): void {
                const value: boolean = !!(this.instance.flags as any)[name].getValue()
                ;(this.instance.flags as any)[name].setValue(value)
                this.writeBits(0, 1, bitOffset, 1, value ? 1 : 0)
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'GRE proto=${protocolType}',
            properties: {
                //Flags/version (byte 0-1, MSB first): C(0) R(1) K(2) S(3) s(4) Recur(5-7) | reserved0(8-12)
                //Version(13-15). The legacy R/s/Recur/reserved bits are kept verbatim for byte-perfect.
                flags: {
                    type: 'object',
                    label: 'Flags',
                    properties: {
                        checksum: this.#flagBit('checksum', 0, 'Checksum Present'),
                        routing: this.#flagBit('routing', 1, 'Routing Present'),
                        key: this.#flagBit('key', 2, 'Key Present'),
                        sequence: this.#flagBit('sequence', 3, 'Sequence Number Present'),
                        strictRoute: this.#flagBit('strictRoute', 4, 'Strict Source Route'),
                        recur: {
                            type: 'integer', label: 'Recursion Control', minimum: 0, maximum: 7, hidden: true,
                            decode: function (this: GRE): void { this.instance.flags.recur.setValue(this.readBits(0, 1, 5, 3)) },
                            encode: function (this: GRE): void { this.writeBits(0, 1, 5, 3, this.instance.flags.recur.getValue(0)) }
                        },
                        reserved0: {
                            type: 'integer', label: 'Reserved', minimum: 0, maximum: 31, hidden: true,
                            decode: function (this: GRE): void { this.instance.flags.reserved0.setValue(this.readBits(1, 1, 0, 5)) },
                            encode: function (this: GRE): void { this.writeBits(1, 1, 0, 5, this.instance.flags.reserved0.getValue(0)) }
                        },
                        version: {
                            type: 'integer', label: 'Version', minimum: 0, maximum: 7,
                            decode: function (this: GRE): void { this.instance.flags.version.setValue(this.readBits(1, 1, 5, 3)) },
                            encode: function (this: GRE): void { this.writeBits(1, 1, 5, 3, this.instance.flags.version.getValue(0)) }
                        }
                    }
                },
                //Protocol Type is the EtherType of the inner frame — stored as a lowercase hex string
                //(like eth.etherType) so it can drive the `ethertype` demux dimension to the inner codec.
                protocolType: {
                    type: 'string', label: 'Protocol Type', contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: GRE): void { this.instance.protocolType.setValue(BufferToHex(this.readBytes(2, 2))) },
                    encode: function (this: GRE): void {
                        const hex: string = this.instance.protocolType.getValue('0800')
                        this.writeBytes(2, HexToBuffer(hex.padStart(4, '0').slice(-4)))
                    }
                },
                checksum: {type: 'integer', label: 'Checksum', minimum: 0, maximum: 65535},
                reserved1: {type: 'string', label: 'Reserved', contentEncoding: StringContentEncodingEnum.HEX, hidden: true},
                keyValue: {type: 'string', label: 'Key', contentEncoding: StringContentEncodingEnum.HEX},
                sequenceNumber: {type: 'integer', label: 'Sequence Number', minimum: 0, maximum: 4294967295},
                //Master field: the optional trailing fields are flag-conditional, so they are parsed/
                //emitted here (runs after the fixed flags/protocolType fields — property order).
                body: {
                    type: 'string', label: 'Body', contentEncoding: StringContentEncodingEnum.HEX, hidden: true,
                    decode: function (this: GRE): void {
                        const available: number = this.#available()
                        const hasChecksum: boolean = !!this.instance.flags.checksum.getValue()
                        const hasKey: boolean = !!this.instance.flags.key.getValue()
                        const hasSeq: boolean = !!this.instance.flags.sequence.getValue()
                        let offset: number = 4
                        if (hasChecksum && offset + 4 <= available) {
                            this.instance.checksum.setValue(BufferToUInt16(this.readBytes(offset, 2)))
                            this.instance.reserved1.setValue(BufferToHex(this.readBytes(offset + 2, 2)))
                            offset += 4
                        }
                        if (hasKey && offset + 4 <= available) {
                            this.instance.keyValue.setValue(BufferToHex(this.readBytes(offset, 4)))
                            offset += 4
                        }
                        if (hasSeq && offset + 4 <= available) {
                            this.instance.sequenceNumber.setValue(BufferToUInt32(this.readBytes(offset, 4)))
                            offset += 4
                        }
                    },
                    encode: function (this: GRE): void {
                        const hasChecksum: boolean = !!this.instance.flags.checksum.getValue()
                        const hasKey: boolean = !!this.instance.flags.key.getValue()
                        const hasSeq: boolean = !!this.instance.flags.sequence.getValue()
                        let offset: number = 4
                        if (hasChecksum) {
                            //Honored verbatim, not recomputed — a crafted GRE may carry any checksum.
                            this.writeBytes(offset, UInt16ToBuffer(this.instance.checksum.getValue(0)))
                            this.writeBytes(offset + 2, HexToBuffer(this.instance.reserved1.getValue('0000')))
                            offset += 4
                        }
                        if (hasKey) {
                            this.writeBytes(offset, HexToBuffer(this.instance.keyValue.getValue('00000000')))
                            offset += 4
                        }
                        if (hasSeq) {
                            this.writeBytes(offset, UInt32ToBuffer(this.instance.sequenceNumber.getValue(0)))
                            offset += 4
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'gre'

    public readonly name: string = 'Generic Routing Encapsulation'

    public readonly nickname: string = 'GRE'

    public readonly matchKeys: string[] = ['ipproto:47']

    public match(): boolean {
        //GRE sits directly above IPv4 (protocol field) or IPv6 (next-header field) with protocol 47, and
        //needs at least its 4-byte base header within the IP payload.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.instance.protocol.getValue() !== 0x2f && this.prevCodecModule.instance.nxt.getValue() !== 0x2f) return false
        return this.#available() >= 4
    }

    //Protocol Type is an EtherType; declaring it in the 'ethertype' namespace dispatches an inner IPv4/
    //IPv6 packet to the O(1) bucket (which accepts a 'gre' parent), while a 0x6558 Ethernet payload
    //falls through to EthernetII's tunnel-aware match.
    public readonly demuxProducers: DemuxProducer[] = [{field: 'protocolType', namespace: 'ethertype', kind: 'string'}]

}
