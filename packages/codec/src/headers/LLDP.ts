import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One LLDP TLV: a 7-bit Type and its verbatim hex Value (the on-wire 9-bit Length = value byte count). */
type LldpTlv = {type: number, value: string}

/**
 * LLDP — Link Layer Discovery Protocol (IEEE 802.1AB), carried directly in an Ethernet II frame with
 * EtherType 0x88CC (an Ethernet child — no IP/UDP). An LLDPDU is a flat sequence of TLVs; each TLV is a
 * 2-byte header — Type (7 bits, the high bits 15..9) + Length (9 bits, bits 8..0, the value byte count) —
 * followed by Length value bytes. The mandatory TLVs come first in order (Chassis ID = 1, Port ID = 2,
 * Time To Live = 3), then zero or more optional TLVs, terminated by the End Of LLDPDU TLV (type 0,
 * length 0). LLDP has no length field of its own — it runs to the end of the frame.
 *
 * TLVs are carried generically (type + verbatim hex value) so every TLV — including optional and
 * organization-specific ones whose value is opaque — round-trips byte-for-byte; per-TLV semantic decoding
 * is a later enrichment. The walk stops at the End TLV (type 0) or when the frame is exhausted; any bytes
 * after the End TLV are Ethernet padding, kept verbatim in `padding` so the frame is reproduced exactly.
 */
export class LLDP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (LLDP.#schemaCache ??= LLDP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'LLDP ${tlvs.length} TLVs',
            properties: {
                tlvs: {
                    type: 'array',
                    label: 'TLVs',
                    items: {
                        type: 'object',
                        label: 'TLV',
                        properties: {
                            type: {type: 'integer', label: 'Type', minimum: 0, maximum: 127},
                            value: {type: 'string', label: 'Value', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: LLDP): void {
                        //LLDP runs to the end of the frame — there is no length field. Bound the walk by the
                        //remaining frame bytes, reading each 2-byte TLV header as type(7)+length(9), MSB-first.
                        const available: number = this.packet.length - this.startPos
                        const tlvs: LldpTlv[] = []
                        let offset: number = 0
                        while (offset + 2 <= available) {
                            const type: number = this.readBits(offset, 2, 0, 7)
                            const length: number = this.readBits(offset, 2, 7, 9)
                            //A value that overruns the frame (truncation) is not consumed — stop and leave the
                            //remaining bytes to `padding`, keeping the round-trip exact.
                            if (offset + 2 + length > available) break
                            const value: string = length > 0 ? BufferToHex(this.readBytes(offset + 2, length)) : ''
                            tlvs.push({type: type, value: value})
                            offset += 2 + length
                            //End Of LLDPDU (type 0): logical end of the PDU — anything after is padding.
                            if (type === 0) break
                        }
                        this.instance.tlvs.setValue(tlvs)
                        //Trailing bytes after the End TLV (or after a truncated TLV) are Ethernet padding.
                        this.instance.padding.setValue(offset < available ? BufferToHex(this.readBytes(offset, available - offset)) : '')
                    },
                    encode: function (this: LLDP): void {
                        const tlvs: LldpTlv[] = this.instance.tlvs.getValue([])
                        let offset: number = 0
                        if (tlvs) {
                            for (let i: number = 0; i < tlvs.length; i++) {
                                const tlv: LldpTlv = tlvs[i]
                                let value: Buffer = HexToBuffer(tlv.value ? tlv.value : '')
                                //The TLV length is a 9-bit field (max 511 bytes). A longer value cannot be
                                //represented, so clamp it and record the error rather than silently wrapping
                                //the length modulo 512 (which would corrupt the following TLVs).
                                if (value.length > 511) {
                                    this.recordError(`tlvs[${i}].value`, 'Maximum TLV value length is 511 bytes')
                                    value = value.subarray(0, 511)
                                }
                                //Pack the 2-byte header: type in the high 7 bits, the value byte count in the
                                //low 9 bits. writeBits masks each field, so type and length never clobber.
                                this.writeBits(offset, 2, 0, 7, tlv.type ? tlv.type : 0)
                                this.writeBits(offset, 2, 7, 9, value.length)
                                offset += 2
                                if (value.length) {
                                    this.writeBytes(offset, value)
                                    offset += value.length
                                }
                            }
                        }
                        const padding: string = this.instance.padding.getValue('')
                        if (padding) this.writeBytes(offset, HexToBuffer(padding))
                    }
                },
                //Ethernet padding after the End Of LLDPDU TLV, kept verbatim. No codec of its own — it is
                //set/read by the `tlvs` field (which owns the single offset walk); this entry is metadata
                //so the editor sees the padding bytes.
                padding: {
                    type: 'string',
                    label: 'Padding',
                    contentEncoding: StringContentEncodingEnum.HEX
                }
            }
        }
    }

    public readonly id: string = 'lldp'

    public readonly name: string = 'Link Layer Discovery Protocol'

    public readonly nickname: string = 'LLDP'

    public readonly matchKeys: string[] = ['ethertype:88cc']

    public match(): boolean {
        //An Ethernet child selected by EtherType 0x88CC (stored as a lowercase 4-hex string). Require the
        //2-byte minimum for one TLV header.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'eth') return false
        if (this.prevCodecModule.instance.etherType.getValue() !== '88cc') return false
        return this.packet.length - this.startPos >= 2
    }

    //A leaf header — nothing demuxes above LLDP.
    public readonly demuxProducers: DemuxProducer[] = []

}
