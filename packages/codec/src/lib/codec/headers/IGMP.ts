import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToIPv4} from '../../helper/BufferToIP'
import {IPv4ToBuffer} from '../../helper/IPToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * IGMP — Internet Group Management Protocol (IGMPv2 RFC 2236, IGMPv3 RFC 3376), carried directly over
 * IPv4 as protocol 2. Every message opens with a fixed 4-byte header — Type (1), Max Resp Code (1) and
 * a 16-bit Checksum (ones-complement over the whole IGMP message) — followed by a type-driven body:
 *
 *  - v1/v2 (Membership Query with total length 8 / Report 0x12 / Report 0x16 / Leave 0x17): a single
 *    4-byte Group Address (dotted-quad).
 *  - v3 Membership Query (Type 0x11 with an IP payload ≥ 12 bytes): Group Address (4) + Resv/S/QRV (1) +
 *    QQIC (1) + Number of Sources (2) + that many 4-byte source addresses, kept verbatim as `sources`
 *    hex (bounded by the source count and the IP payload).
 *  - v3 Membership Report (Type 0x22): 2 reserved bytes + Number of Group Records (2) + the group
 *    records, kept verbatim as `records` hex (bounded by the IP payload).
 *
 * The Checksum is honored verbatim, never recomputed (encode is a faithful executor); a well-formed
 * message round-trips byte-for-byte. The message is bounded by the enclosing IPv4 datagram (total
 * length − IP header length) so trailing padding is left to the codec's recursion / RawData. The v3
 * source/record counts are honor-else-derive; the v3 record structures are kept as bounded hex.
 */
export class IGMP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (IGMP.#schemaCache ??= IGMP.#buildSchema())
    }

    /**
     * Bytes of IGMP the IP layer below says are available: IPv4 carries a total-length field, so the
     * IGMP payload is (total length − IP header length). Mirrors the GRE/OSPF #available() pattern so
     * body reads are bounded by the real on-wire length rather than trusting a count field alone.
     * Returns the captured-bytes remainder when no length is present (0 floor).
     * @private
     */
    #available(): number {
        const prev: any = this.prevCodecModule
        if (!prev) return 0
        const ipv4TotalLength: number = prev.instance.length.getValue(0)
        if (ipv4TotalLength) {
            const payload: number = ipv4TotalLength - prev.length
            return payload < 0 ? 0 : payload
        }
        const remaining: number = this.packet.length - this.startPos
        return remaining < 0 ? 0 : remaining
    }

    /** True when this is an IGMPv3 Membership Query — Type 0x11 with an IP payload of at least 12 bytes. */
    #isV3Query(): boolean {
        const type: number = this.instance.type.getValue(0)
        return type === 0x11 && this.#available() >= 12
    }

    /** True when this is an IGMPv3 Membership Report (Type 0x22): reserved + group records, no group address. */
    #isV3Report(): boolean {
        const type: number = this.instance.type.getValue(0)
        return type === 0x22
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'IGMP type=${type} group=${groupAddress}',
            properties: {
                //==== Fixed 4-byte header (RFC 2236 §2, RFC 3376 §4) ====
                type: this.fieldUInt('type', 0, 1, 'Type'),
                maxRespCode: this.fieldUInt('maxRespCode', 1, 1, 'Max Resp Code'),
                //Honored verbatim: the IGMP checksum (ones-complement over the whole message) is never
                //recomputed, so a captured packet round-trips byte-for-byte even if it lies.
                checksum: this.fieldUInt('checksum', 2, 2, 'Checksum'),
                //==== Group Address (offset 4): present for every type except the v3 Report (0x22),
                //whose bytes 4-7 are reserved + record count instead. ====
                groupAddress: {
                    type: 'string',
                    label: 'Multicast Address',
                    minLength: 7,
                    maxLength: 15,
                    contentEncoding: StringContentEncodingEnum.IPv4,
                    decode: function (this: IGMP): void {
                        if (this.#isV3Report()) return
                        this.instance.groupAddress.setValue(BufferToIPv4(this.readBytes(4, 4)))
                    },
                    encode: function (this: IGMP): void {
                        if (this.#isV3Report()) return
                        const groupAddress: string = this.instance.groupAddress.getValue('0.0.0.0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        this.instance.groupAddress.setValue(groupAddress)
                        this.writeBytes(4, IPv4ToBuffer(groupAddress))
                    }
                },
                //==== IGMPv3 Membership Query body (RFC 3376 §4.1), decoded only when #isV3Query() ====
                resvSQRV: {
                    type: 'integer',
                    label: 'Resv/S/QRV',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: IGMP): void {
                        if (!this.#isV3Query()) return
                        this.instance.resvSQRV.setValue(this.readBytes(8, 1)[0] ?? 0)
                    },
                    encode: function (this: IGMP): void {
                        if (!this.#isV3Query()) return
                        this.writeBytes(8, Buffer.from([this.instance.resvSQRV.getValue(0) & 0xff]))
                    }
                },
                qqic: {
                    type: 'integer',
                    label: 'QQIC',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: IGMP): void {
                        if (!this.#isV3Query()) return
                        this.instance.qqic.setValue(this.readBytes(9, 1)[0] ?? 0)
                    },
                    encode: function (this: IGMP): void {
                        if (!this.#isV3Query()) return
                        this.writeBytes(9, Buffer.from([this.instance.qqic.getValue(0) & 0xff]))
                    }
                },
                numSources: {
                    type: 'integer',
                    label: 'Number of Sources',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: IGMP): void {
                        if (!this.#isV3Query()) return
                        this.instance.numSources.setValue(BufferToUInt16(this.readBytes(10, 2)))
                    },
                    encode: function (this: IGMP): void {
                        if (!this.#isV3Query()) return
                        //honor-else-derive: honored when supplied (a crafted message may lie); else the
                        //number of 4-byte source addresses carried in the `sources` hex.
                        const provided: number | undefined = this.instance.numSources.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : Math.floor(HexToBuffer(this.instance.sources.getValue('')).length / 4)
                        if (value > 65535) {
                            this.recordError(this.instance.numSources.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) value = 0
                        this.instance.numSources.setValue(value)
                        this.writeBytes(10, UInt16ToBuffer(value))
                    }
                },
                //Source addresses (offset 12), Number-of-Sources × 4 bytes, kept verbatim. Bounded by
                //both the source count and the IP payload so a lying count can't read past the datagram;
                //any surplus is left to the codec's recursion / RawData.
                sources: {
                    type: 'string',
                    label: 'Source Addresses',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: IGMP): void {
                        if (!this.#isV3Query()) return
                        const available: number = this.#available()
                        let byteLength: number = this.instance.numSources.getValue(0) * 4
                        const max: number = available - 12
                        if (byteLength > max) byteLength = max
                        if (byteLength > 0) this.instance.sources.setValue(BufferToHex(this.readBytes(12, byteLength)))
                    },
                    encode: function (this: IGMP): void {
                        if (!this.#isV3Query()) return
                        const sources: string = this.instance.sources.getValue('')
                        if (sources) this.writeBytes(12, HexToBuffer(sources))
                    }
                },
                //==== IGMPv3 Membership Report body (RFC 3376 §4.2), decoded only for Type 0x22 ====
                reserved: {
                    type: 'string',
                    label: 'Reserved',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    hidden: true,
                    decode: function (this: IGMP): void {
                        if (!this.#isV3Report()) return
                        this.instance.reserved.setValue(BufferToHex(this.readBytes(4, 2)))
                    },
                    encode: function (this: IGMP): void {
                        if (!this.#isV3Report()) return
                        this.writeBytes(4, HexToBuffer(this.instance.reserved.getValue('0000')))
                    }
                },
                numGroupRecords: {
                    type: 'integer',
                    label: 'Number of Group Records',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: IGMP): void {
                        if (!this.#isV3Report()) return
                        this.instance.numGroupRecords.setValue(BufferToUInt16(this.readBytes(6, 2)))
                    },
                    encode: function (this: IGMP): void {
                        if (!this.#isV3Report()) return
                        //Honored verbatim (a group record is variable-length, so the count is not derived
                        //from the bounded `records` hex); defaults to 0 when not supplied.
                        let value: number = this.instance.numGroupRecords.getValue(0)
                        if (value > 65535) {
                            this.recordError(this.instance.numGroupRecords.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) value = 0
                        this.instance.numGroupRecords.setValue(value)
                        this.writeBytes(6, UInt16ToBuffer(value))
                    }
                },
                //Group records (offset 8), kept verbatim as bounded hex to the end of the IP payload —
                //the group-record structures (record type, aux data, per-record sources) are not
                //sub-decoded in this slice.
                records: {
                    type: 'string',
                    label: 'Group Records',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: IGMP): void {
                        if (!this.#isV3Report()) return
                        const available: number = this.#available()
                        if (available > 8) this.instance.records.setValue(BufferToHex(this.readBytes(8, available - 8)))
                    },
                    encode: function (this: IGMP): void {
                        if (!this.#isV3Report()) return
                        const records: string = this.instance.records.getValue('')
                        if (records) this.writeBytes(8, HexToBuffer(records))
                    }
                }
            }
        }
    }

    public readonly id: string = 'igmp'

    public readonly name: string = 'Internet Group Management Protocol'

    public readonly nickname: string = 'IGMP'

    public readonly matchKeys: string[] = ['ipproto:2']

    public match(): boolean {
        //IGMP sits directly on IPv4 with protocol 2 (accept an IPv6 next-header of 2 too, for symmetry
        //with the other IP-borne codecs), and needs at least its fixed 4-byte header plus a group
        //address (the smallest well-formed v1/v2 message is 8 bytes) within the IP payload.
        if (!this.prevCodecModule) return false
        const protocol: number = this.prevCodecModule.instance.protocol.getValue(0)
        const nextHeader: number = this.prevCodecModule.instance.nxt.getValue(0)
        if (protocol !== 2 && nextHeader !== 2) return false
        return this.#available() >= 8
    }

    //A leaf header — the v3 group-record structures are kept as bounded hex, nothing demuxes off IGMP.
    public readonly demuxProducers: DemuxProducer[] = []

}
