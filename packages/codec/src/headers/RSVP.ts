import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt16} from '../helper/BufferToNumber'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * RSVP — Resource ReSerVation Protocol (RFC 2205), carried directly over IP as protocol 46. Every RSVP
 * message opens with an 8-byte common header: a byte splitting Version (high 4 bits, 1 for RFC 2205) and
 * Flags (low 4 bits), a Message Type (1 Path, 2 Resv, 3 PathErr, 4 ResvErr, 5 PathTear, 6 ResvTear, 7
 * ResvConf), a 2-byte RSVP Checksum, a 1-byte Send_TTL, a 1-byte Reserved, and a 2-byte RSVP Length (the
 * whole message octet count including this common header). The header is followed by a sequence of
 * objects, each a 2-byte Length (the object octet count including its own 4-byte header) + 1-byte
 * Class-Num + 1-byte C-Type + contents.
 *
 * The object contents are class/C-Type specific and several (SESSION, SENDER_TSPEC, FLOWSPEC, …) need
 * cross-object and policy context, so this codec keeps each object's contents verbatim as `data` hex
 * (byte-perfect) and does not sub-decode them. The RSVP Length is honored verbatim when supplied on
 * encode (a crafted message may lie) and derived from the objects otherwise; each object's Length is
 * likewise honored-else-derived. The Checksum is honored verbatim, never recomputed. Object walking is
 * doubly bounded — by the RSVP Length field and by the bytes the IP layer actually made available — so a
 * lying length can't read past the datagram, and trailing / pipelined bytes are left to the codec's
 * recursion / RawData. A well-formed message round-trips byte-for-byte.
 */
export class RSVP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (RSVP.#schemaCache ??= RSVP.#buildSchema())
    }

    /**
     * Bytes of RSVP the IP layer below says are available. IPv4 carries a total-length field, so the
     * RSVP payload is (total length - IP header length); IPv6 carries the payload length directly (plen).
     * Mirrors the OSPF/GRE #available() pattern so object walking is bounded by the real on-wire length
     * rather than trusting the RSVP Length field alone (which a malformed packet may overstate). Falls
     * back to the captured bytes after this header when neither IP length is present.
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

    /**
     * Header-relative end offset of the RSVP message: the RSVP Length field, clamped down to the bytes
     * the IP layer actually made available (#available), and never below the 8-byte common header. Object
     * walking is bounded by this so a corrupt Length can't read past the IP payload, and any bytes beyond
     * it (padding / a pipelined message) fall through to the codec's recursion / RawData.
     * @private
     */
    #messageEnd(): number {
        let end: number = this.instance.length.getValue(0)
        const available: number = this.#available()
        if (available && available < end) end = available
        if (!end || end < 8) end = 8
        if (available && end > available) end = available
        return end
    }

    /** Effective on-wire byte length of one object: its Length field when supplied, else 4 + its data. */
    static #objectLength(object: any): number {
        const provided: number = Number(object && object.length)
        if (Number.isFinite(provided) && provided > 0) return provided
        const data: string = object && object.data ? String(object.data) : ''
        return 4 + HexToBuffer(data).length
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'RSVP msgType=${msgType} len=${length}',
            properties: {
                //==== Common header (8 bytes, RFC 2205 §3.1.1) ====
                //Byte 0 high nibble: Version (1 for RFC 2205). Read/written as its own bit field so the
                //Flags nibble below is preserved (writeBits is read-modify-write).
                version: {
                    type: 'integer',
                    label: 'Version',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: RSVP): void {
                        this.instance.version.setValue(this.readBits(0, 1, 0, 4))
                    },
                    encode: function (this: RSVP): void {
                        const value: number = this.instance.version.getValue(1)
                        this.instance.version.setValue(value)
                        this.writeBits(0, 1, 0, 4, value)
                    }
                },
                //Byte 0 low nibble: Flags. Reserved bits are kept verbatim so a non-canonical frame still
                //round-trips byte-for-byte.
                flags: {
                    type: 'integer',
                    label: 'Flags',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: RSVP): void {
                        this.instance.flags.setValue(this.readBits(0, 1, 4, 4))
                    },
                    encode: function (this: RSVP): void {
                        const value: number = this.instance.flags.getValue(0)
                        this.instance.flags.setValue(value)
                        this.writeBits(0, 1, 4, 4, value)
                    }
                },
                msgType: this.fieldUInt('msgType', 1, 1, 'Message Type'),
                //Honored verbatim: the RSVP checksum (ones-complement over the message) is never
                //recomputed, so a captured message round-trips byte-for-byte. A zero value means no
                //checksum was transmitted (RFC 2205 §3.1.1).
                checksum: this.fieldUInt('checksum', 2, 2, 'Checksum'),
                sendTTL: this.fieldUInt('sendTTL', 4, 1, 'Send TTL'),
                //Reserved byte — kept verbatim and re-emitted for byte-perfect.
                reserved: this.fieldUInt('reserved', 5, 1, 'Reserved'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 8,
                    maximum: 65535,
                    decode: function (this: RSVP): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(6, 2)))
                    },
                    encode: function (this: RSVP): void {
                        //RSVP Length counts the whole message = 8-byte common header + all objects. Honored
                        //when supplied (a crafted message may lie); else derived from the objects.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number
                        if (provided !== undefined && provided !== null) {
                            value = provided
                        } else {
                            const objects: any[] | undefined = this.instance.objects.getValue()
                            let total: number = 8
                            if (Array.isArray(objects)) {
                                for (const object of objects) total += RSVP.#objectLength(object)
                            }
                            value = total
                        }
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 8) value = 8
                        this.instance.length.setValue(value)
                        this.writeBytes(6, UInt16ToBuffer(value))
                    }
                },
                //==== Objects (RFC 2205 §3.1.2) ====
                //Each object: Length(2) + Class-Num(1) + C-Type(1) + contents. Contents kept verbatim as
                //`data` hex (byte-perfect); class/C-Type specific parsing is deliberately not attempted.
                //Walking is bounded by #messageEnd (RSVP Length ∧ IP payload), so a lying object Length
                //can't run past the datagram and trailing bytes are left to the codec.
                objects: {
                    type: 'array',
                    label: 'Objects',
                    items: {
                        type: 'object',
                        properties: {
                            length: {type: 'integer', label: 'Length', minimum: 0, maximum: 65535},
                            classNum: {type: 'integer', label: 'Class-Num', minimum: 0, maximum: 255},
                            cType: {type: 'integer', label: 'C-Type', minimum: 0, maximum: 255},
                            data: {type: 'string', label: 'Data', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: RSVP): void {
                        const end: number = this.#messageEnd()
                        const objects: {length: number, classNum: number, cType: number, data: string}[] = []
                        let offset: number = 8
                        //Each object needs at least its own 4-byte header within the message.
                        while (offset + 4 <= end) {
                            const objectLength: number = BufferToUInt16(this.readBytes(offset, 2, true))
                            const classNum: number = this.readBytes(offset + 2, 1, true)[0]
                            const cType: number = this.readBytes(offset + 3, 1, true)[0]
                            //A Length below the 4-byte header is malformed and would stall the walk —
                            //record it and stop (decode never throws).
                            if (objectLength < 4) {
                                this.recordError(this.instance.objects.getPath(), `Invalid object length ${objectLength}`)
                                break
                            }
                            //Contents run to the object's Length but never past the message end.
                            let dataEnd: number = offset + objectLength
                            if (dataEnd > end) dataEnd = end
                            const dataStart: number = offset + 4
                            const data: string = dataEnd > dataStart ? BufferToHex(this.readBytes(dataStart, dataEnd - dataStart)) : ''
                            objects.push({length: objectLength, classNum: classNum, cType: cType, data: data})
                            offset += objectLength
                        }
                        //The object header bytes are peeked dryRun (so a malformed-length break leaves
                        //them to trailing RawData), and an empty object (Length 4, no contents) does no
                        //non-dry data read of its own. Mark the whole consumed object region with one
                        //non-dry read so headerLength covers every byte the walk captured — otherwise an
                        //empty trailing object is re-decoded as trailing RawData and duplicated on encode.
                        const consumedEnd: number = offset < end ? offset : end
                        if (consumedEnd > 8) this.readBytes(8, consumedEnd - 8)
                        this.instance.objects.setValue(objects)
                    },
                    encode: function (this: RSVP): void {
                        const objects: any[] | undefined = this.instance.objects.getValue()
                        if (!Array.isArray(objects)) return
                        let offset: number = 8
                        for (const object of objects) {
                            const dataBuffer: Buffer = HexToBuffer(object && object.data ? String(object.data) : '')
                            //Object Length honored when supplied (may lie), else derived from contents.
                            const providedLength: number = Number(object && object.length)
                            const lengthValue: number = (Number.isFinite(providedLength) && providedLength > 0)
                                ? providedLength
                                : 4 + dataBuffer.length
                            const classNum: number = Number(object && object.classNum) || 0
                            const cType: number = Number(object && object.cType) || 0
                            this.writeBytes(offset, UInt16ToBuffer(lengthValue > 65535 ? 65535 : lengthValue))
                            this.writeBytes(offset + 2, Buffer.from([classNum & 0xff, cType & 0xff]))
                            if (dataBuffer.length) this.writeBytes(offset + 4, dataBuffer)
                            //Physical layout always advances by the actual bytes written (4 + contents),
                            //independent of a lying Length field — mirrors BGP's honor-else-derive body.
                            offset += 4 + dataBuffer.length
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'rsvp'

    public readonly name: string = 'Resource ReSerVation Protocol'

    public readonly nickname: string = 'RSVP'

    public readonly matchKeys: string[] = ['ipproto:46']

    public match(): boolean {
        if (!this.prevCodecModule) return false
        //RSVP sits directly on IP (protocol 46). Accept the demux value from either the IPv4 protocol
        //field or the IPv6 next-header field, and require at least the full 8-byte common header of IP
        //payload to be present.
        const protocol: number = this.prevCodecModule.instance.protocol.getValue(0)
        const nextHeader: number = this.prevCodecModule.instance.nxt.getValue(0)
        if (protocol !== 46 && nextHeader !== 46) return false
        return this.#available() >= 8
    }

    //A leaf header — object contents require per-class, policy-dependent parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
