import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One collectd part: a TLV kept byte-verbatim — a 2-byte part Type, the on-wire Length, and the
 * value as hex. The Length COUNTS the 4-byte part header (Type + Length), so the value byte count is
 * Length − 4. */
type CollectdPart = {type: number, length: number, value: string}

/**
 * collectd binary network protocol (the monitoring daemon's UDP transport, well-known UDP port 25826,
 * default multicast group 239.192.74.66). A collectd datagram is a flat sequence of parts; each part is
 * a 4-byte header — a 2-byte Type and a 2-byte Length, both big-endian — followed by Length − 4 value
 * bytes (the Length field COUNTS its own 4-byte header). Common part types: 0x0000 Host, 0x0001 Time,
 * 0x0002 Plugin, 0x0004 PluginInstance, 0x0008 Type, 0x0009 Values. There is no top-level length — the
 * datagram owns the whole UDP payload and parts run to its end.
 *
 * Parts are carried generically (Type + on-wire Length + verbatim hex value) so every part — string,
 * numeric, values, or unknown — round-trips byte-for-byte; per-type semantic decoding (string bodies,
 * uint64 times, the Values type/count/data layout) is a later enrichment. The walk peeks each 4-byte
 * header (dry-run), stops at a part that overruns the payload or declares a Length < 4 (its own header),
 * and keeps any bytes after the last complete part verbatim in `trailer` so the datagram is reproduced
 * exactly. Each part's Length is honored verbatim on encode (a crafted part may lie) or derived from the
 * value byte count when absent; the part layout always advances by the actual value bytes written.
 */
export class Collectd extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Collectd.#schemaCache ??= Collectd.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'collectd ${parts.length} parts',
            properties: {
                parts: {
                    type: 'array',
                    label: 'Parts',
                    items: {
                        type: 'object',
                        label: 'Part',
                        properties: {
                            type: {type: 'integer', label: 'Type', minimum: 0, maximum: 65535},
                            //On-wire Length INCLUDING the 4-byte part header (Type + Length). Honored
                            //verbatim on encode; derived as 4 + value bytes when omitted.
                            length: {type: 'integer', label: 'Length', minimum: 0, maximum: 65535},
                            value: {type: 'string', label: 'Value', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: Collectd): void {
                        //The datagram owns the whole UDP payload — there is no outer length, so bound the
                        //walk by the remaining payload bytes. Each part is Type(2) Length(2) Value(Length−4).
                        const available: number = this.packet.length - this.startPos
                        const parts: CollectdPart[] = []
                        let offset: number = 0
                        while (offset + 4 <= available) {
                            //Peek the 4-byte header (dry-run) before committing so a truncated / malformed
                            //part is NOT consumed by the header length — its bytes fall through to `trailer`.
                            const header: Buffer = this.readBytes(offset, 4, true)
                            const type: number = header.readUInt16BE(0)
                            const length: number = header.readUInt16BE(2)
                            //Length counts its own 4-byte header: a value below 4 cannot delimit the part
                            //(and would not advance the offset), so stop and keep the rest as trailer.
                            if (length < 4) break
                            //A part that overruns the payload (truncation) is not consumed — stop and leave
                            //the remaining bytes to `trailer`, keeping the round-trip exact.
                            if (offset + length > available) break
                            //Commit-read the whole part so the header length covers exactly what is consumed.
                            const partBuffer: Buffer = this.readBytes(offset, length)
                            const value: string = length > 4 ? BufferToHex(partBuffer.subarray(4)) : ''
                            parts.push({type: type, length: length, value: value})
                            offset += length
                        }
                        this.instance.parts.setValue(parts)
                        //Any bytes after the last complete part (a truncated / malformed final part, or
                        //padding) are kept verbatim and consumed, so the datagram is reproduced exactly and
                        //collectd always advances to the end of its UDP payload.
                        this.instance.trailer.setValue(offset < available ? BufferToHex(this.readBytes(offset, available - offset)) : '')
                    },
                    encode: function (this: Collectd): void {
                        const parts: CollectdPart[] = this.instance.parts.getValue([])
                        let offset: number = 0
                        if (parts) {
                            for (let i: number = 0; i < parts.length; i++) {
                                const part: CollectdPart = parts[i]
                                let type: number = part.type ? part.type : 0
                                if (type > 65535) {
                                    this.recordError(`parts[${i}].type`, 'Maximum value is 65535')
                                    type = 65535
                                }
                                if (type < 0) {
                                    this.recordError(`parts[${i}].type`, 'Minimum value is 0')
                                    type = 0
                                }
                                const value: Buffer = HexToBuffer(part.value ? part.value : '')
                                //Length is honored when supplied (a crafted part may lie); else derived as
                                //the 4-byte header + value bytes. The layout always advances by the actual
                                //value bytes written, so a lying Length does not shift the next part.
                                const provided: number | undefined = part.length
                                let length: number = (provided !== undefined && provided !== null) ? provided : 4 + value.length
                                if (length > 65535) {
                                    this.recordError(`parts[${i}].length`, 'Maximum value is 65535')
                                    length = 65535
                                }
                                if (length < 0) {
                                    this.recordError(`parts[${i}].length`, 'Minimum value is 0')
                                    length = 0
                                }
                                this.writeBytes(offset, UInt16ToBuffer(type))
                                this.writeBytes(offset + 2, UInt16ToBuffer(length))
                                offset += 4
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
                //Bytes after the last complete part (a truncated/malformed final part, or padding), kept
                //verbatim. No codec of its own — it is set/read by the `parts` field (which owns the single
                //offset walk); this entry is metadata so the editor sees the trailing bytes.
                trailer: {
                    type: 'string',
                    label: 'Trailer',
                    contentEncoding: StringContentEncodingEnum.HEX
                }
            }
        }
    }

    public readonly id: string = 'collectd'

    public readonly name: string = 'collectd Network Protocol'

    public readonly nickname: string = 'collectd'

    public readonly matchKeys: string[] = ['udpport:25826']

    public match(): boolean {
        //collectd rides on UDP port 25826 (selected via the udpport:25826 bucket). Require the 4-byte
        //minimum for one part header. The binary header carries no strong content magic, so the
        //well-known port is the signature — stays a port-bucket protocol (matchKeys only, NO
        //heuristicFallback: a 2-byte part type is far too weak to claim collectd off its port).
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        return this.packet.length - this.startPos >= 4
    }

    //A leaf header — the per-type part bodies are kept verbatim for now.
    public readonly demuxProducers: DemuxProducer[] = []

}
