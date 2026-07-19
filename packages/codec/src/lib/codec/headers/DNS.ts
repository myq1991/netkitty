import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {BufferToUInt8, BufferToUInt16, BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer, UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * A domain name. `value` is the resolved dotted string (following any compression pointers) for
 * display and differential checks; `raw` is the EXACT on-wire bytes of the name at its physical
 * position (local labels + either a null terminator or a 2-byte compression pointer), which is what
 * encode re-emits — so a compressed name round-trips byte-for-byte without having to reconstruct the
 * compression. When crafting a name from scratch (no `raw`), encode falls back to an uncompressed
 * encoding built from `value`.
 */
type DnsName = {value: string, raw: string}

type DnsQuestion = {name: DnsName, qtype: number, qclass: number}

type DnsRecord = {name: DnsName, type: number, class: number, ttl: number, rdlength: number, rdata: string}

/**
 * DNS — Domain Name System (RFC 1035), the message carried over UDP port 53. A 12-byte header (ID,
 * flags, and the four section counts) followed by the Question, Answer, Authority and Additional
 * sections. Names use label compression (RFC 1035 §4.1.4): a length octet with its top two bits set
 * (0xC0) is a 14-bit pointer to an earlier offset in the message.
 *
 * Byte-perfect strategy: every name keeps its exact wire bytes (`raw`) and every record's RDATA is
 * kept as raw hex, so compression pointers — inside names and inside RDATA (CNAME/NS/SOA/MX targets) —
 * are reproduced verbatim; the resolved dotted name (`value`) is a decoded convenience. Per-RDATA
 * semantic decoding (A → address, etc.) is a later enrichment on top of this faithful base. DNS over
 * TCP (which prefixes a 2-byte length and can span segments) is out of scope for this single-packet
 * codec and belongs to the reassembly layer.
 */
export class DNS extends BaseHeader {

    //Running parse/emit cursor shared across the four section closures (they run in schema order:
    //questions → answers → authorities → additionals). Header-relative; the header is 12 bytes.
    #cursor: number = 12

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (DNS.#schemaCache ??= DNS.#buildSchema())
    }

    static #flagBit(name: string, byteOffset: number, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'boolean',
            label: label,
            decode: function (this: DNS): void {
                (this.instance.flags as any)[name].setValue(!!this.readBits(byteOffset, 1, bitOffset, 1))
            },
            encode: function (this: DNS): void {
                const value: boolean = !!(this.instance.flags as any)[name].getValue()
                ;(this.instance.flags as any)[name].setValue(value)
                this.writeBits(byteOffset, 1, bitOffset, 1, value ? 1 : 0)
            }
        }
    }

    static #flagInt(name: string, byteOffset: number, bitOffset: number, bitLength: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: (1 << bitLength) - 1,
            decode: function (this: DNS): void {
                (this.instance.flags as any)[name].setValue(this.readBits(byteOffset, 1, bitOffset, bitLength))
            },
            encode: function (this: DNS): void {
                const value: number = (this.instance.flags as any)[name].getValue(0)
                this.writeBits(byteOffset, 1, bitOffset, bitLength, value)
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        const nameSchema: ProtocolFieldJSONSchema = {
            type: 'object',
            label: 'Name',
            properties: {
                value: {type: 'string', label: 'Name'},
                raw: {type: 'string', label: 'Raw', contentEncoding: StringContentEncodingEnum.HEX, hidden: true}
            }
        }
        return {
            type: 'object',
            summary: 'DNS ${id} queries=${qdcount} answers=${ancount}',
            properties: {
                id: this.fieldUInt('id', 0, 2, 'Transaction ID'),
                //Byte 2 (bit 0 = MSB): QR, Opcode[4], AA, TC, RD. Byte 3: RA, Z, AD, CD, RCODE[4].
                flags: {
                    type: 'object',
                    label: 'Flags',
                    properties: {
                        qr: this.#flagBit('qr', 2, 0, 'Response'),
                        opcode: this.#flagInt('opcode', 2, 1, 4, 'Opcode'),
                        aa: this.#flagBit('aa', 2, 5, 'Authoritative'),
                        tc: this.#flagBit('tc', 2, 6, 'Truncated'),
                        rd: this.#flagBit('rd', 2, 7, 'Recursion Desired'),
                        ra: this.#flagBit('ra', 3, 0, 'Recursion Available'),
                        z: this.#flagBit('z', 3, 1, 'Reserved'),
                        ad: this.#flagBit('ad', 3, 2, 'Authentic Data'),
                        cd: this.#flagBit('cd', 3, 3, 'Checking Disabled'),
                        rcode: this.#flagInt('rcode', 3, 4, 4, 'Reply Code')
                    }
                },
                qdcount: this.fieldUInt('qdcount', 4, 2, 'Questions'),
                ancount: this.fieldUInt('ancount', 6, 2, 'Answer RRs'),
                nscount: this.fieldUInt('nscount', 8, 2, 'Authority RRs'),
                arcount: this.fieldUInt('arcount', 10, 2, 'Additional RRs'),
                questions: {
                    type: 'array',
                    label: 'Queries',
                    items: {
                        type: 'object',
                        label: 'Query',
                        properties: {
                            name: nameSchema,
                            qtype: {type: 'integer', label: 'Type', minimum: 0, maximum: 65535},
                            qclass: {type: 'integer', label: 'Class', minimum: 0, maximum: 65535}
                        }
                    },
                    decode: function (this: DNS): void {
                        const count: number = this.instance.qdcount.getValue(0)
                        const available: number = this.packet.length - this.startPos
                        const questions: DnsQuestion[] = []
                        let offset: number = 12
                        for (let i: number = 0; i < count && offset < available; i++) {
                            const nameEnd: {name: DnsName, next: number} = this.readName(offset)
                            let o: number = nameEnd.next
                            const qtype: number = BufferToUInt16(this.readBytes(o, 2))
                            o += 2
                            const qclass: number = BufferToUInt16(this.readBytes(o, 2))
                            o += 2
                            questions.push({name: nameEnd.name, qtype: qtype, qclass: qclass})
                            offset = o
                        }
                        this.#cursor = offset
                        this.instance.questions.setValue(questions)
                    },
                    encode: function (this: DNS): void {
                        const questions: DnsQuestion[] | undefined = this.instance.questions.getValue()
                        let offset: number = 12
                        if (questions) {
                            for (const question of questions) {
                                offset = this.writeName(offset, question.name)
                                this.writeBytes(offset, UInt16ToBuffer(question.qtype ? question.qtype : 0))
                                offset += 2
                                this.writeBytes(offset, UInt16ToBuffer(question.qclass ? question.qclass : 0))
                                offset += 2
                            }
                        }
                        this.#cursor = offset
                    }
                },
                answers: this.#recordSection('answers', 'Answers', 'ancount'),
                authorities: this.#recordSection('authorities', 'Authoritative nameservers', 'nscount'),
                additionals: this.#recordSection('additionals', 'Additional records', 'arcount')
            }
        }
    }

    //A resource-record section (Answer/Authority/Additional): NAME TYPE CLASS TTL RDLENGTH RDATA, each
    //continuing from the shared cursor. RDLENGTH is derived from the RDATA byte length on encode.
    static #recordSection(field: string, label: string, countField: string): ProtocolFieldJSONSchema {
        const nameSchema: ProtocolFieldJSONSchema = {
            type: 'object',
            label: 'Name',
            properties: {
                value: {type: 'string', label: 'Name'},
                raw: {type: 'string', label: 'Raw', contentEncoding: StringContentEncodingEnum.HEX, hidden: true}
            }
        }
        return {
            type: 'array',
            label: label,
            items: {
                type: 'object',
                label: 'Resource Record',
                properties: {
                    name: nameSchema,
                    type: {type: 'integer', label: 'Type', minimum: 0, maximum: 65535},
                    class: {type: 'integer', label: 'Class', minimum: 0, maximum: 65535},
                    ttl: {type: 'integer', label: 'Time to Live', minimum: 0, maximum: 4294967295},
                    rdlength: {type: 'integer', label: 'Data Length', minimum: 0, maximum: 65535},
                    rdata: {type: 'string', label: 'Data', contentEncoding: StringContentEncodingEnum.HEX}
                }
            },
            decode: function (this: DNS): void {
                const count: number = (this.instance as any)[countField].getValue(0)
                const available: number = this.packet.length - this.startPos
                const records: DnsRecord[] = []
                let offset: number = this.#cursor
                for (let i: number = 0; i < count && offset < available; i++) {
                    const nameEnd: {name: DnsName, next: number} = this.readName(offset)
                    let o: number = nameEnd.next
                    const type: number = BufferToUInt16(this.readBytes(o, 2))
                    o += 2
                    const cls: number = BufferToUInt16(this.readBytes(o, 2))
                    o += 2
                    const ttl: number = BufferToUInt32(this.readBytes(o, 4))
                    o += 4
                    const rdlength: number = BufferToUInt16(this.readBytes(o, 2))
                    o += 2
                    let rdata: string = ''
                    if (rdlength) {
                        rdata = BufferToHex(this.readBytes(o, rdlength))
                        o += rdlength
                    }
                    records.push({name: nameEnd.name, type: type, class: cls, ttl: ttl, rdlength: rdlength, rdata: rdata})
                    offset = o
                }
                this.#cursor = offset
                ;(this.instance as any)[field].setValue(records)
            },
            encode: function (this: DNS): void {
                const records: DnsRecord[] | undefined = (this.instance as any)[field].getValue()
                let offset: number = this.#cursor
                if (records) {
                    for (const record of records) {
                        offset = this.writeName(offset, record.name)
                        this.writeBytes(offset, UInt16ToBuffer(record.type ? record.type : 0))
                        offset += 2
                        this.writeBytes(offset, UInt16ToBuffer(record.class ? record.class : 0))
                        offset += 2
                        this.writeBytes(offset, UInt32ToBuffer(record.ttl ? record.ttl : 0))
                        offset += 4
                        const rdata: Buffer = Buffer.from(record.rdata ? record.rdata : '', 'hex')
                        //RDLENGTH is authoritatively the RDATA byte length — derive it (byte-perfect,
                        //since the decoded RDLENGTH equals the RDATA length).
                        this.writeBytes(offset, UInt16ToBuffer(rdata.length))
                        offset += 2
                        if (rdata.length) {
                            this.writeBytes(offset, rdata)
                            offset += rdata.length
                        }
                    }
                }
                this.#cursor = offset
            }
        }
    }

    /**
     * Parse the name at header-relative `offset`. Returns the resolved value + exact physical raw bytes
     * and the offset just past the physical name. Compression pointers are followed only to build the
     * resolved value (dry-run reads that never grow headerLength); the physical bytes are the local
     * labels plus the terminating null OR the 2-byte pointer, so endPos stays exact.
     */
    protected readName(offset: number): {name: DnsName, next: number} {
        const labels: string[] = []
        const visited: Set<number> = new Set()
        let o: number = offset
        let physicalEnd: number = -1
        let guard: number = 0
        while (guard++ < 256) {
            if (visited.has(o)) break
            visited.add(o)
            const len: number = BufferToUInt8(this.readBytes(o, 1, true))
            if (len === 0) {
                if (physicalEnd < 0) physicalEnd = o + 1
                break
            }
            if ((len & 0xc0) === 0xc0) {
                const pointer: number = ((len & 0x3f) << 8) | BufferToUInt8(this.readBytes(o + 1, 1, true))
                if (physicalEnd < 0) physicalEnd = o + 2
                o = pointer
                continue
            }
            labels.push(this.readBytes(o + 1, len, true).toString('latin1'))
            o = o + 1 + len
        }
        if (physicalEnd < 0) physicalEnd = o
        const rawLength: number = physicalEnd - offset
        //Physically read the local name bytes (non-dry-run) so headerLength/endPos cover them.
        const raw: string = rawLength > 0 ? BufferToHex(this.readBytes(offset, rawLength)) : ''
        return {name: {value: labels.join('.'), raw: raw}, next: physicalEnd}
    }

    /**
     * Write a name at `offset`. Re-emits the exact `raw` wire bytes when present (byte-perfect for a
     * decoded name, including its compression pointer); otherwise builds an uncompressed encoding from
     * the dotted `value` (for names crafted from scratch). Returns the offset past the written name.
     */
    protected writeName(offset: number, name: DnsName | undefined): number {
        const raw: string = name && name.raw ? name.raw : ''
        if (raw) {
            const rawBuffer: Buffer = Buffer.from(raw, 'hex')
            this.writeBytes(offset, rawBuffer)
            return offset + rawBuffer.length
        }
        let o: number = offset
        const value: string = name && name.value ? name.value : ''
        if (value.length) {
            for (const label of value.split('.')) {
                const labelBuffer: Buffer = Buffer.from(label, 'latin1')
                this.writeBytes(o, UInt8ToBuffer(labelBuffer.length))
                o += 1
                this.writeBytes(o, labelBuffer)
                o += labelBuffer.length
            }
        }
        this.writeBytes(o, UInt8ToBuffer(0))
        o += 1
        return o
    }

    public readonly id: string = 'dns'

    public readonly name: string = 'Domain Name System'

    public readonly nickname: string = 'DNS'

    //Port-defined (udp:53). DNS has no content signature, so no heuristicFallback. DNS over TCP uses a
    //2-byte length prefix and can span segments — that is a reassembly-layer concern, not this codec.
    public readonly matchKeys: string[] = ['udpport:53']

    public match(): boolean {
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp'
    }

    //A leaf header — nothing demuxes above DNS.
    public readonly demuxProducers: DemuxProducer[] = []

}
