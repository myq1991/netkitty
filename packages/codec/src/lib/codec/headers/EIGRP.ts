import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One EIGRP TLV: a 2-byte Type, a 2-byte Length (the whole TLV octet count incl. this 4-byte header)
 *  and the verbatim hex Value (Length - 4 bytes). */
type EigrpTlv = {type: number, length: number, value: string}

/**
 * EIGRP — Enhanced Interior Gateway Routing Protocol (Cisco), carried directly over IP as protocol 88.
 * Every EIGRP packet begins with a fixed 20-byte header — Version (1), Opcode (1: 1 Update, 3 Query,
 * 4 Reply, 5 Hello, 10 SIA-Query, 11 SIA-Reply), Checksum (2, the IP-style ones-complement checksum
 * over the whole EIGRP packet), Flags (4), Sequence (4), Acknowledge (4), Virtual Router ID (2) and
 * Autonomous System number (2) — followed by a chain of TLVs. Each TLV is a 2-byte Type, a 2-byte
 * Length (the total TLV octet count including the 4-byte TLV header) and Length-4 value bytes.
 *
 * The TLV chain has no terminator/count, so the walk is bounded by the enclosing IP payload (like GRE /
 * OSPF #available) — a lying Length near the end never reads into a trailing FCS/padding. TLV values are
 * kept verbatim as hex (per-TLV route/parameter bodies are opaque here), so every TLV round-trips
 * byte-for-byte; the Length is honored when supplied (a crafted TLV may lie) else derived from the value
 * byte count. The Checksum is honored verbatim, never recomputed (encode is a faithful executor). A
 * well-formed packet round-trips byte-for-byte. Leaf header — TLV sub-structures are not sub-decoded.
 */
export class EIGRP extends BaseHeader {

    /**
     * Bytes of EIGRP the IP layer below says are available. IPv4 carries a total-length field, so the
     * EIGRP payload is (total length - IP header length); IPv6 carries the payload length directly
     * (plen). Mirrors the GRE / OSPF #available() pattern so the TLV walk is bounded by the real on-wire
     * length rather than the captured frame (which may include Ethernet padding after the IP payload).
     * @private
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

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (EIGRP.#schemaCache ??= EIGRP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'EIGRP opcode=${opcode} as=${autonomousSystem}',
            properties: {
                //==== Fixed 20-byte header ====
                version: this.fieldUInt('version', 0, 1, 'Version'),
                opcode: this.fieldUInt('opcode', 1, 1, 'Opcode'),
                //Honored verbatim: the EIGRP checksum (ones-complement over the whole packet with the
                //checksum field zeroed) is never recomputed, so a captured packet round-trips byte-for-byte.
                checksum: this.fieldUInt('checksum', 2, 2, 'Checksum'),
                flags: this.fieldUInt('flags', 4, 4, 'Flags'),
                sequence: this.fieldUInt('sequence', 8, 4, 'Sequence'),
                ack: this.fieldUInt('ack', 12, 4, 'Acknowledge'),
                virtualRouterId: this.fieldUInt('virtualRouterId', 16, 2, 'Virtual Router ID'),
                autonomousSystem: this.fieldUInt('autonomousSystem', 18, 2, 'Autonomous System'),
                //==== TLV chain (type + length-incl-header + verbatim value) ====
                tlvs: {
                    type: 'array',
                    label: 'TLVs',
                    items: {
                        type: 'object',
                        label: 'TLV',
                        properties: {
                            type: {type: 'integer', label: 'Type', minimum: 0, maximum: 65535},
                            length: {type: 'integer', label: 'Length', minimum: 0, maximum: 65535},
                            value: {type: 'string', label: 'Value', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: EIGRP): void {
                        //The TLV chain has no terminator/count — bound the walk by the IP payload so a
                        //corrupt Length can't read past the datagram into an FCS/padding. Each TLV is a
                        //2-byte Type + 2-byte Length (whole-TLV octet count incl. the 4-byte header).
                        const available: number = this.#available()
                        const tlvs: EigrpTlv[] = []
                        let offset: number = 20
                        while (offset + 4 <= available) {
                            const type: number = BufferToUInt16(this.readBytes(offset, 2))
                            const length: number = BufferToUInt16(this.readBytes(offset + 2, 2))
                            //Value byte count = Length - 4; clamp to the bytes actually available (a lying
                            //Length is stored verbatim but never over-reads). The step is always >= 4, so
                            //the walk cannot stall even on a zero/undersized Length.
                            let valueLen: number = length - 4
                            if (valueLen < 0) valueLen = 0
                            if (offset + 4 + valueLen > available) valueLen = available - offset - 4
                            const value: string = valueLen > 0 ? BufferToHex(this.readBytes(offset + 4, valueLen)) : ''
                            tlvs.push({type: type, length: length, value: value})
                            offset += 4 + valueLen
                        }
                        this.instance.tlvs.setValue(tlvs)
                    },
                    encode: function (this: EIGRP): void {
                        const tlvs: EigrpTlv[] = this.instance.tlvs.getValue([])
                        let offset: number = 20
                        if (tlvs) {
                            for (let i: number = 0; i < tlvs.length; i++) {
                                const tlv: EigrpTlv = tlvs[i]
                                const value: Buffer = HexToBuffer(tlv.value ? tlv.value : '')
                                let type: number = tlv.type ? tlv.type : 0
                                if (type > 65535) {
                                    this.recordError(`tlvs[${i}].type`, 'Maximum value is 65535')
                                    type = 65535
                                }
                                if (type < 0) type = 0
                                //Length is honored when supplied (a crafted TLV may lie about its size),
                                //else derived from the 4-byte header + the actual value byte count.
                                let length: number = (tlv.length !== undefined && tlv.length !== null)
                                    ? tlv.length
                                    : 4 + value.length
                                if (length > 65535) {
                                    this.recordError(`tlvs[${i}].length`, 'Maximum value is 65535')
                                    length = 65535
                                }
                                if (length < 0) length = 0
                                this.writeBytes(offset, UInt16ToBuffer(type))
                                this.writeBytes(offset + 2, UInt16ToBuffer(length))
                                offset += 4
                                if (value.length) {
                                    this.writeBytes(offset, value)
                                    offset += value.length
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'eigrp'

    public readonly name: string = 'Enhanced Interior Gateway Routing Protocol'

    public readonly nickname: string = 'EIGRP'

    public readonly matchKeys: string[] = ['ipproto:88']

    public match(): boolean {
        //EIGRP sits directly on IP (protocol 88). Accept the demux value from either the IPv4 protocol
        //field or the IPv6 next-header field, and require at least the fixed 20-byte header of IP payload.
        if (!this.prevCodecModule) return false
        const protocol: number = this.prevCodecModule.instance.protocol.getValue(0)
        const nextHeader: number = this.prevCodecModule.instance.nxt.getValue(0)
        if (protocol !== 88 && nextHeader !== 88) return false
        return this.#available() >= 20
    }

    //A leaf header — EIGRP TLV bodies are kept as verbatim hex, nothing demuxes above it.
    public readonly demuxProducers: DemuxProducer[] = []

}
