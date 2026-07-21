import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One SCTP chunk. `length` is the on-wire Chunk Length (the 4-byte chunk header + value, NOT the
 *  trailing 4-byte-alignment padding); `value` is the chunk-specific value portion as lower-case hex;
 *  `padding` is the verbatim 0..3 pad bytes kept so the packet round-trips byte-for-byte. */
type SCTPChunk = {type: number, flags: number, length: number, value: string, padding: string}

/**
 * SCTP — Stream Control Transmission Protocol (RFC 9260), carried directly over IP as protocol 132
 * (both IPv4 `protocol` and IPv6 `nxt`). The 12-byte common header is all big-endian: Source Port (2) +
 * Destination Port (2) + Verification Tag (4) + Checksum (4). The Checksum is a CRC32c over the whole
 * SCTP packet (with the field zeroed) stored little-endian on the wire — but it is honored verbatim,
 * never recomputed (encode is a faithful executor), so it is surfaced as an opaque 4-byte hex string.
 *
 * After the common header comes a chain of chunks until the enclosing IP payload is consumed. Each chunk
 * is Type(1) + Flags(1) + Length(2) + Value, where Length counts the 4-byte chunk header plus the value
 * but NOT the trailing padding to the next 4-byte boundary. Because the Length excludes that pad, the
 * alignment padding (0..3 bytes) is the tricky part of a byte-perfect round-trip: it is captured verbatim
 * (per chunk, as hex) and re-emitted, so even a malformed non-zero pad reproduces exactly. Chunks are
 * carried generically (type + flags + verbatim hex value) so every chunk type — DATA(0), INIT(1),
 * INIT_ACK(2), SACK(3), HEARTBEAT(4), HEARTBEAT_ACK(5), COOKIE_ECHO(10), COOKIE_ACK(11), … — round-trips;
 * per-chunk semantic decoding (and cross-packet DATA reassembly) is a later enrichment.
 *
 * The chunk walk is bounded by the enclosing IP datagram, so a lying chunk Length near the end does not
 * read into a trailing Ethernet FCS; a chunk whose Length overruns the available bytes (or is below its
 * own 4-byte header) stops the walk, leaving the remainder to the codec's recursion / RawData. A
 * well-formed SCTP packet round-trips byte-for-byte. This is a single-packet codec: chunks are dissected
 * in place, with no cross-packet reassembly.
 */
export class SCTP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SCTP.#schemaCache ??= SCTP.#buildSchema())
    }

    /**
     * Bytes available to SCTP within the enclosing IP datagram — so a short IP payload (or a lying chunk
     * Length) does not let the chunk walk read into a trailing Ethernet FCS / padding. Bounds the chunk
     * reads and the match gate.
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

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SCTP ${srcPort}->${dstPort}',
            properties: {
                srcPort: this.fieldUInt('srcPort', 0, 2, 'Source Port'),
                dstPort: this.fieldUInt('dstPort', 2, 2, 'Destination Port'),
                //32-bit association selector; opaque on the wire, kept verbatim as hex.
                verificationTag: this.fieldHex('verificationTag', 4, 4, 'Verification Tag'),
                //CRC32c over the whole packet (little-endian on the wire) — honored verbatim, never
                //recomputed, so it is surfaced as opaque 4-byte hex and round-trips even when crafted/wrong.
                checksum: this.fieldHex('checksum', 8, 4, 'Checksum'),
                chunks: {
                    type: 'array',
                    label: 'Chunks',
                    items: {
                        type: 'object',
                        label: 'Chunk',
                        properties: {
                            type: {type: 'integer', label: 'Chunk Type', minimum: 0, maximum: 255},
                            flags: {type: 'integer', label: 'Chunk Flags', minimum: 0, maximum: 255},
                            length: {type: 'integer', label: 'Chunk Length', minimum: 0, maximum: 65535},
                            value: {type: 'string', label: 'Value', contentEncoding: StringContentEncodingEnum.HEX},
                            padding: {type: 'string', label: 'Padding', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: SCTP): void {
                        const available: number = this.#available()
                        const chunks: SCTPChunk[] = []
                        let offset: number = 12
                        //Each chunk is type(1) flags(1) length(2) value. A Length below its own 4-byte
                        //header is invalid (and would not advance), and a Length that overruns the
                        //available bytes is truncated — in both cases stop and leave the remaining bytes
                        //to the codec's recursion / raw layer, keeping the round-trip exact.
                        while (offset + 4 <= available) {
                            const type: number = BufferToUInt8(this.readBytes(offset, 1, true))
                            const flags: number = BufferToUInt8(this.readBytes(offset + 1, 1, true))
                            const chunkLength: number = BufferToUInt16(this.readBytes(offset + 2, 2, true))
                            if (chunkLength < 4 || offset + chunkLength > available) break
                            //Padding to the next 4-byte boundary is NOT counted in chunkLength; for a
                            //well-formed packet it is within `available` (clamped defensively otherwise).
                            const padLength: number = (4 - (chunkLength % 4)) % 4
                            const padAvailable: number = Math.min(padLength, available - (offset + chunkLength))
                            const valueLength: number = chunkLength - 4
                            chunks.push({
                                type: type,
                                flags: flags,
                                length: chunkLength,
                                value: valueLength > 0 ? BufferToHex(this.readBytes(offset + 4, valueLength)) : '',
                                padding: padAvailable > 0 ? BufferToHex(this.readBytes(offset + chunkLength, padAvailable)) : ''
                            })
                            offset += chunkLength + padAvailable
                        }
                        //The chunk-header reads (type/flags/length) are dryRun peeks so a malformed-length
                        //break leaves the bytes to trailing RawData; an empty-value chunk (COOKIE_ACK /
                        //SHUTDOWN_ACK, Length 4) does no non-dry value/padding read of its own. Mark the
                        //whole consumed chunk region with one non-dry read so headerLength covers every
                        //byte the walk captured — otherwise a trailing empty chunk is re-decoded as a
                        //RawData layer and duplicated on encode (the packet grows and re-encode differs).
                        if (offset > 12) this.readBytes(12, offset - 12)
                        this.instance.chunks.setValue(chunks)
                    },
                    encode: function (this: SCTP): void {
                        const chunks: SCTPChunk[] = this.instance.chunks.getValue([])
                        if (!chunks) return
                        let offset: number = 12
                        for (const chunk of chunks) {
                            const type: number = chunk.type ? chunk.type : 0
                            const flags: number = chunk.flags ? chunk.flags : 0
                            const value: Buffer = HexToBuffer(chunk.value ? chunk.value : '')
                            //Honor an explicit Chunk Length (a crafted chunk may lie / a decoded one carries
                            //its on-wire value); else derive it from the 4-byte header + value. For a decoded
                            //chunk these agree exactly, so the walk advances identically to decode.
                            const chunkLength: number = (chunk.length !== undefined && chunk.length !== null)
                                ? chunk.length
                                : 4 + value.length
                            this.writeBytes(offset, UInt8ToBuffer(type))
                            this.writeBytes(offset + 1, UInt8ToBuffer(flags))
                            this.writeBytes(offset + 2, UInt16ToBuffer(chunkLength))
                            if (value.length) this.writeBytes(offset + 4, value)
                            //Padding kept verbatim so a non-zero/truncated pad round-trips; when absent
                            //(crafting) it is derived as zero bytes to the next 4-byte boundary.
                            const padding: Buffer = (chunk.padding !== undefined && chunk.padding !== null)
                                ? HexToBuffer(chunk.padding)
                                : Buffer.alloc((4 - (chunkLength % 4)) % 4, 0)
                            if (padding.length) this.writeBytes(offset + chunkLength, padding)
                            offset += chunkLength + padding.length
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'sctp'

    public readonly name: string = 'Stream Control Transmission Protocol'

    public readonly nickname: string = 'SCTP'

    public readonly matchKeys: string[] = ['ipproto:132']

    public match(): boolean {
        //SCTP sits directly above IPv4 (protocol field) or IPv6 (next-header field) with protocol 132,
        //and needs at least its 12-byte common header within the IP payload.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.instance.protocol.getValue() !== 0x84 && this.prevCodecModule.instance.nxt.getValue() !== 0x84) return false
        return this.#available() >= 12
    }

    //A leaf header — chunk values are kept as hex, not demuxed further.
    public readonly demuxProducers: DemuxProducer[] = []

}
