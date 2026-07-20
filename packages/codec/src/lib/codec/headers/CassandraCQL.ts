import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Cassandra CQL native protocol (DataStax/Apache Cassandra, native protocol v4), TCP port 9042. Every
 * CQL frame begins with a fixed 9-byte big-endian header — Version (the direction bit 0x80 OR-ed with
 * the protocol version, so 0x04 = a v4 request, 0x84 = a v4 response), Flags, a 2-byte Stream id, an
 * Opcode (0x01 STARTUP, 0x02 READY, 0x05 OPTIONS, 0x07 QUERY, 0x08 RESULT, 0x09 PREPARE, …), and a
 * 4-byte Length (the octet count of the body that follows) — followed by `Length` bytes of
 * opcode-specific body.
 *
 * The body layout differs per opcode (STARTUP's [string map], QUERY's query + consistency, RESULT's
 * kind + rows metadata, …) and several bodies need query-prepare / paging context, so this
 * single-frame codec keeps the body verbatim as `body` hex (byte-perfect) and does not sub-decode it.
 * The Length is auto-computed from the body on encode when not supplied, else honored verbatim (a
 * crafted frame may lie); the body is bounded by the Length so a second pipelined CQL frame or trailing
 * bytes are left to the codec's recursion / RawData. A well-formed frame round-trips byte-for-byte.
 */
export class CassandraCQL extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (CassandraCQL.#schemaCache ??= CassandraCQL.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'CQL v=${version} opcode=${opcode} len=${length}',
            properties: {
                //Version octet: direction bit 0x80 (request 0, response 1) OR-ed with the protocol
                //version in the low 7 bits (e.g. 0x04 v4 request, 0x84 v4 response). Kept as the full
                //octet so both the direction bit and the version round-trip; the split is UI enrichment.
                version: this.fieldUInt('version', 0, 1, 'Version'),
                //Frame flags (bit 0 compression, bit 1 tracing, bit 2 custom payload, bit 3 warning).
                flags: this.fieldUInt('flags', 1, 1, 'Flags'),
                //Stream id correlating requests with responses (may be negative on the wire for
                //server-initiated events; kept as a plain 2-byte value — byte-perfect and editable).
                stream: this.fieldUInt('stream', 2, 2, 'Stream'),
                //Opcode naming the message (0x01 STARTUP, 0x02 READY, 0x05 OPTIONS, 0x07 QUERY,
                //0x08 RESULT, 0x09 PREPARE, …). Plain uint8 so any opcode round-trips.
                opcode: this.fieldUInt('opcode', 4, 1, 'Opcode'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: CassandraCQL): void {
                        this.instance.length.setValue(BufferToUInt32(this.readBytes(5, 4)))
                    },
                    encode: function (this: CassandraCQL): void {
                        //Length counts only the body that follows the 9-byte header. Honored when supplied
                        //(a crafted frame may lie); else derived from the body.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(5, UInt32ToBuffer(value))
                    }
                },
                //The opcode-specific body after the 9-byte header, kept verbatim. Bounded by the Length
                //field (the body ends at offset 9 + Length) and the captured bytes, so trailing /
                //pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: CassandraCQL): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        let end: number = 9 + length
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 9 ? BufferToHex(this.readBytes(9, end - 9)) : '')
                    },
                    encode: function (this: CassandraCQL): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(9, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'cql'

    public readonly name: string = 'Cassandra CQL'

    public readonly nickname: string = 'CQL'

    public readonly matchKeys: string[] = ['tcpport:9042']

    public match(): boolean {
        //Cassandra CQL rides on TCP port 9042. The 9-byte header carries no strong content magic (the
        //version octet's low nibble is just a small protocol version), so the well-known port is the
        //signature: require the previous layer to be TCP and the full 9-byte header to be present. Stays
        //port-bucketed (matchKeys only, no heuristicFallback) so non-CQL 9042 traffic falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        return this.packet.length - this.startPos >= 9
    }

    //A leaf header — the opcode-specific body requires per-opcode, cross-frame parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
