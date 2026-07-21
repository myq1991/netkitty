import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One GLBP TLV: a 1-byte Type, the 1-byte on-wire Length (the WHOLE TLV size incl. this 2-byte header)
 *  and the verbatim hex Value (Length − 2 bytes). */
type GlbpTlv = {type: number, length: number, value: string}

/**
 * GLBP — Gateway Load Balancing Protocol (Cisco), carried over UDP port 3222 to the multicast group
 * 224.0.0.102. Each message begins with a fixed 12-byte header — Version, Unknown1, Group (the GLBP
 * group number), a 2-byte Unknown2 and a 6-byte Owner ID (a MAC address) — followed by a flat sequence
 * of TLVs. Each TLV is a 1-byte Type + 1-byte Length (the length of the WHOLE TLV including this 2-byte
 * header) + Length−2 value bytes (Hello = 1, Request/Response = 2, Auth = 3).
 *
 * GLBP is undocumented; the field names follow Wireshark's dissector, which treats byte 0 (labelled
 * "Version?") as a discriminator that must equal 1 and Unknown1 (bytes must be ≤ 4) — real captures
 * carry Version 1. It is kept as a plain uint8 here (no enum) so encode stays a faithful executor able
 * to craft any value. The TLV value is kept verbatim as hex so every TLV — Hello, Request/Response,
 * Auth, or unknown — round-trips byte-for-byte; per-TLV semantic decoding is a later enrichment. The
 * TLV walk is bounded by the UDP datagram (so retained ethernet padding/FCS is not absorbed); any bytes
 * after the last complete TLV are kept verbatim in `trailing` so the frame is reproduced exactly. GLBP
 * is a leaf — nothing rides on top of it.
 */
export class GLBP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (GLBP.#schemaCache ??= GLBP.#buildSchema())
    }

    /** The payload length bounded by the UDP datagram (so retained ethernet padding/FCS is not absorbed). */
    #payloadLength(): number {
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
            summary: 'GLBP group=${group} v=${version}',
            properties: {
                //Byte 0 — Wireshark labels this "Version?" and its heuristic requires it to equal 1 (real
                //captures carry 1). Kept as a plain uint8 (no enum) so encode can craft any value.
                version: this.fieldUInt('version', 0, 1, 'Version'),
                //Byte 1 — Wireshark's "Unknown1" (its heuristic bounds it to ≤ 4). Kept verbatim.
                unknown1: this.fieldUInt('unknown1', 1, 1, 'Unknown1'),
                //Group number (big-endian).
                group: this.fieldUInt('group', 2, 2, 'Group'),
                //A 2-byte opaque field, kept verbatim so a non-canonical frame stays byte-perfect.
                unknown2: this.fieldHex('unknown2', 4, 2, 'Unknown2'),
                //Owner ID — a 6-byte MAC address, kept verbatim as hex (byte-perfect; MAC formatting is
                //UI enrichment for later).
                ownerId: this.fieldHex('ownerId', 6, 6, 'Owner ID'),
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
                    decode: function (this: GLBP): void {
                        //TLVs run from the end of the 12-byte header to the end of the UDP payload — GLBP
                        //has no length field of its own. The on-wire Length is the WHOLE TLV size (incl.
                        //the 2-byte header), so the value is Length−2 bytes.
                        const available: number = this.#payloadLength()
                        const tlvs: GlbpTlv[] = []
                        let offset: number = 12
                        while (offset + 2 <= available) {
                            const type: number = this.readBytes(offset, 1)[0]
                            const length: number = this.readBytes(offset + 1, 1)[0]
                            //A Length < 2 cannot even cover its own 2-byte header — stop rather than loop
                            //forever, leaving the remaining bytes to `trailing` so the round-trip is exact.
                            if (length < 2) break
                            //A TLV that overruns the payload (truncation) is not consumed — stop and leave
                            //the remaining bytes to `trailing`, keeping the round-trip exact.
                            if (offset + length > available) break
                            const valueLength: number = length - 2
                            const value: string = valueLength > 0 ? BufferToHex(this.readBytes(offset + 2, valueLength)) : ''
                            tlvs.push({type: type, length: length, value: value})
                            offset += length
                        }
                        this.instance.tlvs.setValue(tlvs)
                        //Bytes after the last complete TLV (truncation / trailing) are kept verbatim.
                        this.instance.trailing.setValue(offset < available ? BufferToHex(this.readBytes(offset, available - offset)) : '')
                    },
                    encode: function (this: GLBP): void {
                        const tlvs: GlbpTlv[] = this.instance.tlvs.getValue([])
                        let offset: number = 12
                        if (tlvs) {
                            for (let i: number = 0; i < tlvs.length; i++) {
                                const tlv: GlbpTlv = tlvs[i]
                                const value: Buffer = HexToBuffer(tlv.value ? tlv.value : '')
                                //Length is honored when supplied (a crafted TLV may carry any Length),
                                //else derived as the whole TLV size = 2-byte header + value bytes. It is a
                                //1-byte field, so clamp to [0, 255] (recording an error, never throwing).
                                const providedLength: number | undefined = tlv.length
                                let length: number = (providedLength !== undefined && providedLength !== null)
                                    ? providedLength
                                    : value.length + 2
                                if (length > 255) {
                                    this.recordError(`tlvs[${i}].length`, 'Maximum value is 255')
                                    length = 255
                                }
                                if (length < 0) {
                                    this.recordError(`tlvs[${i}].length`, 'Minimum value is 0')
                                    length = 0
                                }
                                this.writeBytes(offset, Buffer.from([tlv.type ? tlv.type & 0xff : 0, length]))
                                offset += 2
                                if (value.length) {
                                    this.writeBytes(offset, value)
                                    offset += value.length
                                }
                            }
                        }
                        const trailing: string = this.instance.trailing.getValue('')
                        if (trailing) this.writeBytes(offset, HexToBuffer(trailing))
                    }
                },
                //Bytes after the last complete TLV, kept verbatim. No codec of its own — it is set/read by
                //the `tlvs` field (which owns the single offset walk); this entry is metadata so the editor
                //sees the trailing bytes.
                trailing: {
                    type: 'string',
                    label: 'Trailing',
                    contentEncoding: StringContentEncodingEnum.HEX
                }
            }
        }
    }

    public readonly id: string = 'glbp'

    public readonly name: string = 'Gateway Load Balancing Protocol'

    public readonly nickname: string = 'GLBP'

    public readonly matchKeys: string[] = ['udpport:3222']

    public match(): boolean {
        //GLBP rides on UDP port 3222. Require the full 12-byte fixed header within the UDP payload
        //(bounded by the datagram length, not the frame, so ethernet padding is not miscounted); a
        //shorter datagram is not a GLBP message and falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        return this.#payloadLength() >= 12
    }

    //A leaf header — nothing is carried on top of a GLBP message.
    public readonly demuxProducers: DemuxProducer[] = []

}
