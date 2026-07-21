import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {UInt8ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * DCCP — Datagram Congestion Control Protocol (RFC 4340), carried directly over IP as protocol 33. The
 * generic header begins with Source Port (2), Destination Port (2), Data Offset (1, in 32-bit words —
 * the length of the whole DCCP header including options), a byte split into CCVal (high 4 bits) and
 * CsCov (low 4 bits), a 2-byte Checksum, and a byte split into Res (3 bits), Type (4 bits — 0 Request,
 * 1 Response, 2 Data, 3 Ack, 4 DataAck, 5 CloseReq, 6 Close, 7 Reset) and X (1 bit, Extended Sequence
 * Numbers). After that byte come the (X-dependent-width) Reserved + Sequence Number and any type-specific
 * fields / options — everything up to Data Offset*4.
 *
 * To sidestep the X sequence-width branch and stay byte-perfect, this codec structures only the fixed
 * 9-byte prefix (ports / data offset / ccval+cscov / checksum / res+type+x) and keeps the remainder of
 * the header — Reserved, the Sequence/Ack numbers, per-type fields and options — verbatim as
 * `headerOptions` hex (bytes 9 .. DataOffset*4). Application data after the header is kept as `payload`
 * hex, bounded by the enclosing IP datagram so an inflated Data Offset can't read past the IP payload.
 * The Checksum is honored verbatim, never recomputed; Data Offset is honored when supplied, else derived
 * from the actual bytes. A well-formed datagram round-trips byte-for-byte.
 */
export class DCCP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (DCCP.#schemaCache ??= DCCP.#buildSchema())
    }

    /**
     * Bytes of DCCP the IP layer below says are available. IPv4 carries a total-length field, so the
     * DCCP payload is (total length - IP header length); IPv6 carries the payload length directly
     * (plen). Mirrors the GRE/OSPF #available() pattern so header-option and payload reads are bounded
     * by the real on-wire length rather than trusting Data Offset alone. Returns the captured remainder
     * when neither IP length is present.
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

    /**
     * Header-relative end offset of the DCCP header = Data Offset*4, clamped down to the bytes the IP
     * layer actually made available. Both `headerOptions` (which starts at the fixed 9-byte prefix) and
     * the `payload` split are bounded by this.
     */
    #headerEnd(): number {
        let end: number = this.instance.dataOffset.getValue(0) * 4
        const available: number = this.#available()
        if (end > available) end = available
        if (end < 0) end = 0
        return end
    }

    /** A big-endian bit-slice within a single octet at `offset`, read/written in place. */
    static #bitField(name: string, offset: number, bitOffset: number, bitLength: number, label: string): ProtocolFieldJSONSchema {
        const maximum: number = (2 ** bitLength) - 1
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: maximum,
            decode: function (this: DCCP): void {
                (this.instance as any)[name].setValue(this.readBits(offset, 1, bitOffset, bitLength))
            },
            encode: function (this: DCCP): void {
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0)
                if (value > maximum) value = maximum
                if (value < 0) value = 0
                node.setValue(value)
                this.writeBits(offset, 1, bitOffset, bitLength, value)
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'DCCP ${srcPort}→${dstPort} type=${type}',
            properties: {
                srcPort: this.fieldUInt('srcPort', 0, 2, 'Source Port'),
                dstPort: this.fieldUInt('dstPort', 2, 2, 'Destination Port'),
                //Data Offset (32-bit words) = the length of the whole DCCP header incl. options. Honored
                //when supplied (a crafted datagram may lie); else derived from the fixed 9-byte prefix
                //plus the verbatim headerOptions bytes, rounded up to a word.
                dataOffset: {
                    type: 'integer',
                    label: 'Data Offset',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: DCCP): void {
                        this.instance.dataOffset.setValue(this.readBytes(4, 1)[0])
                    },
                    encode: function (this: DCCP): void {
                        const provided: number | undefined = this.instance.dataOffset.getValue()
                        let value: number
                        if (provided !== undefined && provided !== null) {
                            value = provided
                        } else {
                            const optBytes: number = HexToBuffer(this.instance.headerOptions.getValue('')).length
                            value = Math.ceil((9 + optBytes) / 4)
                        }
                        if (value > 255) {
                            this.recordError(this.instance.dataOffset.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) value = 0
                        this.instance.dataOffset.setValue(value)
                        this.writeBytes(4, UInt8ToBuffer(value))
                    }
                },
                //Byte 5: CCVal (high 4 bits) + CsCov (low 4 bits).
                ccval: this.#bitField('ccval', 5, 0, 4, 'CCVal'),
                cscov: this.#bitField('cscov', 5, 4, 4, 'Checksum Coverage'),
                //Honored verbatim: the DCCP checksum (ones-complement over pseudo-header + coverage) is
                //never recomputed, so a captured datagram round-trips byte-for-byte.
                checksum: this.fieldUInt('checksum', 6, 2, 'Checksum'),
                //Byte 8: Res (3 bits) + Type (4 bits) + X (1 bit, Extended Sequence Numbers).
                res: this.#bitField('res', 8, 0, 3, 'Reserved'),
                type: this.#bitField('type', 8, 3, 4, 'Type'),
                x: this.#bitField('x', 8, 7, 1, 'Extended Sequence Numbers'),
                //Everything after the fixed 9-byte prefix up to Data Offset*4 — Reserved, the
                //(X-dependent) Sequence/Ack numbers, per-type fields and options — kept verbatim so the
                //X sequence-width branch never has to be modelled. Bounded by #headerEnd.
                headerOptions: {
                    type: 'string',
                    label: 'Header Options',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: DCCP): void {
                        const end: number = this.#headerEnd()
                        this.instance.headerOptions.setValue(end > 9 ? BufferToHex(this.readBytes(9, end - 9)) : '')
                    },
                    encode: function (this: DCCP): void {
                        const headerOptions: string = this.instance.headerOptions.getValue('')
                        if (headerOptions) this.writeBytes(9, HexToBuffer(headerOptions))
                    }
                },
                //Application data after the DCCP header, kept verbatim. Runs from Data Offset*4 to the end
                //of the IP payload (a leaf — DCCP consumes the whole IP datagram, nothing recurses after).
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: DCCP): void {
                        const available: number = this.#available()
                        let start: number = this.instance.dataOffset.getValue(0) * 4
                        if (start < 9) start = 9
                        if (start > available) start = available
                        this.instance.payload.setValue(available > start ? BufferToHex(this.readBytes(start, available - start)) : '')
                    },
                    encode: function (this: DCCP): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (!payload) return
                        let start: number = this.instance.dataOffset.getValue(0) * 4
                        if (start < 9) start = 9
                        this.writeBytes(start, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'dccp'

    public readonly name: string = 'Datagram Congestion Control Protocol'

    public readonly nickname: string = 'DCCP'

    public readonly matchKeys: string[] = ['ipproto:33']

    public match(): boolean {
        //DCCP sits directly on IPv4 (protocol field) or IPv6 (next-header field) with protocol 33, and
        //needs at least the smallest generic header (12 bytes, X=0) of IP payload present.
        if (!this.prevCodecModule) return false
        const protocol: number = this.prevCodecModule.instance.protocol.getValue(0)
        const nextHeader: number = this.prevCodecModule.instance.nxt.getValue(0)
        if (protocol !== 33 && nextHeader !== 33) return false
        return this.#available() >= 12
    }

    //A leaf header — application data is kept verbatim as `payload` hex.
    public readonly demuxProducers: DemuxProducer[] = []

}
