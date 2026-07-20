import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One Babel TLV: an 8-bit Type and (for every type except Pad1) its verbatim hex Value. */
type BabelTlv = {type: number, length?: number, value?: string}

/**
 * Babel routing protocol (RFC 8966), carried in UDP over port 6696 (to the well-known multicast group
 * or unicast). A Babel packet starts with a fixed 4-byte header — Magic (== 42), Version (== 2) and a
 * 2-byte Body Length (the octet count of the packet body that follows the header, not counting the
 * optional packet trailer) — followed by the packet body: a flat sequence of TLVs, then an optional
 * trailer (which may only carry Pad1/PadN sub-TLVs).
 *
 * Each TLV is Type (1 byte) + Length (1 byte, the value byte count, NOT counting the Type/Length pair)
 * + Value, except Pad1 (Type 0) which is a single byte with no Length/Value. Common types: 0 Pad1,
 * 1 PadN, 2 Acknowledgment Request, 4 Hello, 5 IHU, 8 Update.
 *
 * Byte-perfect strategy (minimal slice): structure Magic / Version / Body Length, then carry the TLVs
 * generically (Type + verbatim hex Value, Pad1 special-cased as a bare byte) so every TLV — including
 * types this codec does not sub-decode — round-trips byte-for-byte. The TLV walk is bounded by Body
 * Length AND the UDP payload (udp.length − 8), so a lying Body Length cannot read past the datagram.
 * Body Length is honored when supplied (a crafted packet may lie) else derived from the TLVs; any bytes
 * after the body (the packet trailer, or leftover bytes from a truncated TLV) are kept verbatim in
 * `trailer` so the datagram is reproduced exactly. A well-formed packet round-trips byte-for-byte.
 */
export class Babel extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Babel.#schemaCache ??= Babel.#buildSchema())
    }

    /**
     * Header-relative end offset of the bytes this Babel layer may consume, so a lying Body Length never
     * reads past the real UDP payload. Over UDP the bound is (udp.length − 8); clamped to the captured
     * bytes. Anything beyond is another datagram / Ethernet padding and is left alone.
     */
    #payloadEnd(): number {
        let end: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpLength: number = prev.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < end) end = udpLength - 8
        }
        return end < 0 ? 0 : end
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Babel v${version} ${tlvs.length} TLVs',
            properties: {
                //The Magic byte, always 42 (0x2a) for Babel — also the match signature on UDP 6696.
                magic: this.fieldUInt('magic', 0, 1, 'Magic'),
                //The protocol version, always 2 (RFC 8966).
                version: this.fieldUInt('version', 1, 1, 'Version'),
                //The octet count of the packet body (the TLV sequence) following this 4-byte header, NOT
                //counting the optional packet trailer. Honored when supplied (a crafted packet may lie)
                //else derived from the TLVs. Derived from the TLV VALUES (not written bytes), so it is
                //correct even though it encodes before the `tlvs` field writes them.
                bodyLength: {
                    type: 'integer',
                    label: 'Body Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: Babel): void {
                        this.instance.bodyLength.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: Babel): void {
                        const provided: number | undefined = this.instance.bodyLength.getValue()
                        let value: number
                        if (provided !== undefined && provided !== null) {
                            value = provided
                        } else {
                            const tlvs: BabelTlv[] = this.instance.tlvs.getValue([])
                            let total: number = 0
                            if (tlvs) {
                                for (const tlv of tlvs) {
                                    //Pad1 (Type 0) is a single byte; every other TLV is Type + Length + Value.
                                    if (tlv && tlv.type === 0) total += 1
                                    else total += 2 + HexToBuffer(tlv && tlv.value ? tlv.value : '').length
                                }
                            }
                            value = total
                        }
                        if (value > 65535) {
                            this.recordError(this.instance.bodyLength.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.bodyLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.bodyLength.setValue(value)
                        this.writeBytes(2, UInt16ToBuffer(value))
                    }
                },
                //The packet body: a flat sequence of TLVs. This single field owns the whole body walk
                //(it also sets/writes `trailer`, which is metadata-only). Bounded by Body Length AND the
                //UDP payload so a truncated / lying packet is contained.
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
                    decode: function (this: Babel): void {
                        const payloadEnd: number = this.#payloadEnd()
                        let bodyEnd: number = 4 + this.instance.bodyLength.getValue(0)
                        if (bodyEnd > payloadEnd) bodyEnd = payloadEnd
                        const tlvs: BabelTlv[] = []
                        let offset: number = 4
                        while (offset < bodyEnd) {
                            const type: number = BufferToUInt8(this.readBytes(offset, 1))
                            //Pad1 (Type 0): a single byte, no Length / Value.
                            if (type === 0) {
                                tlvs.push({type: 0})
                                offset += 1
                                continue
                            }
                            //Need the Type + Length pair; a truncated header stops the walk.
                            if (offset + 2 > bodyEnd) break
                            const length: number = BufferToUInt8(this.readBytes(offset + 1, 1))
                            //A Value that overruns the body (truncation) is not consumed — stop and leave
                            //the remaining bytes to `trailer`, keeping the round-trip exact.
                            if (offset + 2 + length > bodyEnd) break
                            const value: string = length > 0 ? BufferToHex(this.readBytes(offset + 2, length)) : ''
                            tlvs.push({type: type, length: length, value: value})
                            offset += 2 + length
                        }
                        this.instance.tlvs.setValue(tlvs)
                        //Everything after the consumed body up to the UDP payload end is the packet trailer
                        //(Pad1/PadN sub-TLVs) or leftover bytes from a truncated TLV — kept verbatim.
                        this.instance.trailer.setValue(offset < payloadEnd ? BufferToHex(this.readBytes(offset, payloadEnd - offset)) : '')
                    },
                    encode: function (this: Babel): void {
                        const tlvs: BabelTlv[] = this.instance.tlvs.getValue([])
                        let offset: number = 4
                        if (tlvs) {
                            for (let i: number = 0; i < tlvs.length; i++) {
                                const tlv: BabelTlv = tlvs[i]
                                const type: number = tlv && tlv.type ? tlv.type : 0
                                //Pad1 (Type 0): emit the bare Type byte, no Length / Value.
                                if (type === 0) {
                                    this.writeBytes(offset, UInt8ToBuffer(0))
                                    offset += 1
                                    continue
                                }
                                let value: Buffer = HexToBuffer(tlv && tlv.value ? tlv.value : '')
                                //The Length is a single byte (max 255). A longer value cannot be represented,
                                //so clamp it and record the error rather than silently wrapping modulo 256
                                //(which would corrupt the following TLVs).
                                if (value.length > 255) {
                                    this.recordError(`tlvs[${i}].value`, 'Maximum TLV value length is 255 bytes')
                                    value = value.subarray(0, 255)
                                }
                                //Length honored when supplied (a crafted TLV may lie) else derived from the
                                //value byte count.
                                const providedLength: number | undefined = tlv ? tlv.length : undefined
                                let length: number = (providedLength !== undefined && providedLength !== null) ? providedLength : value.length
                                if (length > 255) length = 255
                                if (length < 0) length = 0
                                this.writeBytes(offset, UInt8ToBuffer(type))
                                this.writeBytes(offset + 1, UInt8ToBuffer(length))
                                offset += 2
                                if (value.length) {
                                    this.writeBytes(offset, value)
                                    offset += value.length
                                }
                            }
                        }
                        const trailer: string = this.instance.trailer.getValue('')
                        if (trailer) this.writeBytes(offset, HexToBuffer(trailer))
                    }
                },
                //The optional packet trailer after the body (Pad1/PadN sub-TLVs), or leftover bytes from a
                //truncated TLV, kept verbatim. No codec of its own — it is set/written by the `tlvs` field
                //(which owns the single offset walk); this entry is metadata so the editor sees the bytes.
                trailer: {
                    type: 'string',
                    label: 'Trailer',
                    contentEncoding: StringContentEncodingEnum.HEX
                }
            }
        }
    }

    public readonly id: string = 'babel'

    public readonly name: string = 'Babel Routing Protocol'

    public readonly nickname: string = 'Babel'

    public readonly matchKeys: string[] = ['udpport:6696']

    public match(): boolean {
        //Babel rides on UDP port 6696 (selected via the udpport:6696 bucket). Require the 4-byte header
        //within the UDP payload and the Magic signature (== 42), so non-Babel traffic on 6696 falls
        //through to raw. Stays a port-bucket protocol: matchKeys only, NO heuristicFallback — a lone
        //0x2a byte is too weak a signature to claim Babel off its well-known port.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.#payloadEnd() < 4) return false
        return BufferToUInt8(this.readBytes(0, 1, true)) === 42
    }

    //A leaf header — the per-type TLV bodies are kept verbatim for now.
    public readonly demuxProducers: DemuxProducer[] = []

}
