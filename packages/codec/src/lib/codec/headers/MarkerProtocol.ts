import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8} from '../../helper/BufferToNumber'
import {UInt8ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One Marker PDU TLV: a 1-byte Type, its on-wire 1-byte Length (which counts the 2 header octets too), and its verbatim hex Value. */
type MarkerTlv = {type: number, length: number, value: string}

/**
 * Marker Protocol — the Link Aggregation Marker Protocol (IEEE 802.3ad / 802.1AX), the second of the
 * Slow Protocols carried directly in an Ethernet II frame with EtherType 0x8809 (an Ethernet child — no
 * IP/UDP). It shares the frame type with LACP and is disambiguated by byte 0, the Slow-Protocols
 * Subtype: 1 = LACP (claimed by the LACP header), 2 = Marker (claimed here). Byte 1 is the Version.
 * What follows is a flat sequence of TLVs — each a 1-byte Type + 1-byte Length (the Length counts the 2
 * header octets, so the value is Length-2 bytes) + value bytes: the Marker Information TLV (type 0x01,
 * len 0x10) or Marker Response TLV (type 0x02, len 0x10) — carrying Requester_Port (2), Requester_System
 * (6), Requester_Transaction_ID (4) and Pad (2) — then the Terminator (type 0x00, len 0x00). After the
 * Terminator the PDU is padded with reserved octets to fill the fixed PDU length. Marker has no length
 * field of its own — it runs to the end of the frame.
 *
 * TLVs are carried generically (type + on-wire length + verbatim hex value) so every TLV round-trips
 * byte-for-byte; per-TLV semantic decoding (requester port/system/transaction id) is a later enrichment.
 * The Length is honored verbatim on encode when supplied (a crafted PDU may lie), else derived from the
 * value (2 + value bytes; 0 for the Terminator). The walk stops at the Terminator (type 0) or when the
 * frame is exhausted; any bytes after the Terminator are the reserved padding, kept verbatim in
 * `reserved` so the frame is reproduced exactly.
 */
export class MarkerProtocol extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (MarkerProtocol.#schemaCache ??= MarkerProtocol.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Marker v${version} ${tlvs.length} TLVs',
            properties: {
                subtype: this.fieldUInt('subtype', 0, 1, 'Subtype'),
                version: this.fieldUInt('version', 1, 1, 'Version'),
                tlvs: {
                    type: 'array',
                    label: 'TLVs',
                    items: {
                        type: 'object',
                        label: 'TLV',
                        properties: {
                            type: {type: 'integer', label: 'Type', minimum: 0, maximum: 255},
                            length: {type: 'integer', label: 'Length', minimum: 0, maximum: 255},
                            value: {type: 'string', label: 'Value', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: MarkerProtocol): void {
                        //The Marker PDU runs to the end of the frame — there is no length field. Bound the
                        //walk by the remaining frame bytes. Each TLV is Type(1) + Length(1) + (Length-2)
                        //value bytes; the on-wire Length counts the 2 header octets (the Terminator is the
                        //exception: Length 0).
                        const available: number = this.packet.length - this.startPos
                        const tlvs: MarkerTlv[] = []
                        let offset: number = 2
                        while (offset + 2 <= available) {
                            const type: number = BufferToUInt8(this.readBytes(offset, 1))
                            const length: number = BufferToUInt8(this.readBytes(offset + 1, 1))
                            //Terminator (type 0): logical end of the PDU — anything after is reserved padding.
                            if (type === 0) {
                                tlvs.push({type: type, length: length, value: ''})
                                offset += 2
                                break
                            }
                            //Value byte count = Length - 2 (Length includes the 2 header octets). A malformed
                            //Length < 2 yields no value; a value that overruns the frame (truncation) is not
                            //consumed — stop and leave the remaining bytes to `reserved`, keeping round-trip exact.
                            const valueLength: number = length > 2 ? length - 2 : 0
                            if (offset + 2 + valueLength > available) break
                            const value: string = valueLength > 0 ? BufferToHex(this.readBytes(offset + 2, valueLength)) : ''
                            tlvs.push({type: type, length: length, value: value})
                            offset += 2 + valueLength
                        }
                        this.instance.tlvs.setValue(tlvs)
                        //Trailing bytes after the Terminator (or after a truncated TLV) are the reserved padding.
                        this.instance.reserved.setValue(offset < available ? BufferToHex(this.readBytes(offset, available - offset)) : '')
                    },
                    encode: function (this: MarkerProtocol): void {
                        const tlvs: MarkerTlv[] = this.instance.tlvs.getValue([])
                        let offset: number = 2
                        if (tlvs) {
                            for (let i: number = 0; i < tlvs.length; i++) {
                                const tlv: MarkerTlv = tlvs[i]
                                const type: number = tlv.type ? tlv.type : 0
                                const value: Buffer = HexToBuffer(tlv.value ? tlv.value : '')
                                //Length is honored verbatim when supplied (a crafted PDU may lie), else derived:
                                //value bytes + the 2 header octets (0 for the Terminator, which carries no value).
                                let length: number = (tlv.length !== undefined && tlv.length !== null)
                                    ? tlv.length
                                    : (type === 0 ? 0 : value.length + 2)
                                if (length > 255) {
                                    this.recordError(`tlvs[${i}].length`, 'Maximum value is 255')
                                    length = 255
                                }
                                if (length < 0) {
                                    this.recordError(`tlvs[${i}].length`, 'Minimum value is 0')
                                    length = 0
                                }
                                this.writeBytes(offset, UInt8ToBuffer(type & 0xff))
                                this.writeBytes(offset + 1, UInt8ToBuffer(length))
                                offset += 2
                                if (value.length) {
                                    this.writeBytes(offset, value)
                                    offset += value.length
                                }
                            }
                        }
                        const reserved: string = this.instance.reserved.getValue('')
                        if (reserved) this.writeBytes(offset, HexToBuffer(reserved))
                    }
                },
                //Reserved padding after the Terminator TLV, kept verbatim. No codec of its own — it is
                //set/read by the `tlvs` field (which owns the single offset walk); this entry is metadata
                //so the editor sees the padding bytes.
                reserved: {
                    type: 'string',
                    label: 'Reserved',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    hidden: true
                }
            }
        }
    }

    public readonly id: string = 'marker'

    public readonly name: string = 'Link Aggregation Marker Protocol'

    public readonly nickname: string = 'Marker'

    public readonly matchKeys: string[] = ['ethertype:8809']

    public match(): boolean {
        //An Ethernet child selected by EtherType 0x8809 (Slow Protocols, stored as a lowercase 4-hex
        //string). Only Subtype 2 (Marker) is claimed — Subtype 1 (LACP) and others fall through. Require
        //at least the 2-byte Subtype + Version so the subtype probe is in-bounds.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'eth') return false
        if (this.prevCodecModule.instance.etherType.getValue() !== '8809') return false
        if (this.packet.length - this.startPos < 2) return false
        return BufferToUInt8(this.readBytes(0, 1, true)) === 2
    }

    //A leaf header — nothing demuxes above the Marker Protocol.
    public readonly demuxProducers: DemuxProducer[] = []

}
