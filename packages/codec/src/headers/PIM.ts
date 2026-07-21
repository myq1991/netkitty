import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * PIM — Protocol Independent Multicast, Sparse Mode version 2 (RFC 7761), carried directly over IP as
 * protocol 103. Every PIM message begins with a fixed 4-byte header: a byte whose high nibble is the
 * Version (2 for PIMv2) and low nibble is the message Type, a Reserved byte, and a 2-byte Checksum,
 * followed by the type-specific body.
 *
 * Type selects the body layout — 0 Hello, 1 Register, 2 Register-Stop, 3 Join/Prune, 4 Bootstrap,
 * 5 Assert, 8 Candidate-RP-Advertisement — and several bodies embed Encoded-Address / Encoded-Group /
 * Encoded-Source structures whose parsing depends on address-family and PIM-neighbour context, so this
 * single-message codec keeps the body verbatim as `body` hex (byte-perfect) and does not sub-decode it.
 * The Checksum and Reserved byte are honored verbatim, never recomputed (encode is a faithful executor);
 * a well-formed PIM message round-trips byte-for-byte. The body is bounded by the enclosing IP payload
 * so a trailing FCS / pipelined data is left to the codec's recursion / RawData.
 */
export class PIM extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (PIM.#schemaCache ??= PIM.#buildSchema())
    }

    /**
     * Bytes the IP layer below says are available to PIM. IPv4 carries a total-length field, so the PIM
     * payload is (total length - IP header length); IPv6 carries the payload length directly (plen).
     * Mirrors the GRE #available() pattern so the body decode is bounded by the real on-wire length
     * rather than reading to the end of the captured frame (which would swallow Ethernet padding / FCS).
     * Returns the captured remainder when neither IP length is present.
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

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'PIM v${version} type=${type}',
            properties: {
                //Byte 0: high nibble Version (2 for PIMv2), low nibble Type.
                version: {
                    type: 'integer',
                    label: 'Version',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: PIM): void {
                        this.instance.version.setValue(this.readBits(0, 1, 0, 4))
                    },
                    encode: function (this: PIM): void {
                        const value: number = this.instance.version.getValue(2)
                        this.instance.version.setValue(value)
                        this.writeBits(0, 1, 0, 4, value)
                    }
                },
                type: {
                    type: 'integer',
                    label: 'Type',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: PIM): void {
                        this.instance.type.setValue(this.readBits(0, 1, 4, 4))
                    },
                    encode: function (this: PIM): void {
                        const value: number = this.instance.type.getValue(0)
                        this.instance.type.setValue(value)
                        this.writeBits(0, 1, 4, 4, value)
                    }
                },
                //Byte 1: Reserved (0 on transmit for most types, a flags/subtype byte for a few). Kept
                //verbatim and re-emitted so a non-canonical frame is still byte-perfect.
                reserved: this.fieldHex('reserved', 1, 1, 'Reserved'),
                //Bytes 2-3: Checksum (ones-complement over the PIM message). Honored verbatim, never
                //recomputed, so a captured message round-trips byte-for-byte.
                checksum: this.fieldUInt('checksum', 2, 2, 'Checksum'),
                //The type-specific body after the 4-byte header, kept verbatim. Bounded by the enclosing
                //IP payload (#available) so trailing FCS / pipelined data is left to the codec's recursion.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: PIM): void {
                        const end: number = this.#available()
                        this.instance.body.setValue(end > 4 ? BufferToHex(this.readBytes(4, end - 4)) : '')
                    },
                    encode: function (this: PIM): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(4, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'pim'

    public readonly name: string = 'Protocol Independent Multicast'

    public readonly nickname: string = 'PIM'

    public readonly matchKeys: string[] = ['ipproto:103']

    public match(): boolean {
        //PIM sits directly above IPv4 (protocol field) or IPv6 (next-header field) with protocol 103,
        //and needs at least its 4-byte fixed header within the IP payload.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.instance.protocol.getValue() !== 103 && this.prevCodecModule.instance.nxt.getValue() !== 103) return false
        return this.#available() >= 4
    }

    //A leaf header — the type-specific body (Encoded-Address structures, RP sets, …) needs per-type,
    //address-family-dependent parsing. Inner recursion is deferred to a later serial slice.
    public readonly demuxProducers: DemuxProducer[] = []

}
