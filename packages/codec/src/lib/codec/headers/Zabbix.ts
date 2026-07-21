import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Zabbix protocol (the Zabbix server / agent / sender header), TCP port 10051 (and 10050 for the
 * passive agent). Every message begins with a fixed 13-byte header — a 4-byte Magic ("ZBXD",
 * 0x5A425844), a 1-byte Flags octet (0x01 uncompressed, 0x02 compressed, 0x04 large-packet), a 4-byte
 * Data Length and a 4-byte Reserved field — followed by `Data Length` bytes of body (a JSON request /
 * response, or, when the compressed flag is set, zlib-deflated JSON with the uncompressed size carried
 * in Reserved).
 *
 * ⚠️ Both length fields are LITTLE-ENDIAN (Zabbix serializes them low byte first). There is no
 * little-endian helper in this codebase, so the uint32 fields are read and written byte-by-byte in
 * their closures. For the classic (non large-packet) header Data Length / Reserved are 32-bit; the
 * large-packet variant widens them to 64 bits, which is out of scope for this 13-byte header — the
 * low 32 bits are decoded and a body beyond 4 GiB is not a concern for a single captured segment.
 *
 * The body is the JSON payload (or compressed blob); it is application-level, cross-message state, so
 * this single-message codec keeps it verbatim as `body` hex (byte-perfect) and does not parse the JSON.
 * Data Length is auto-computed from the body on encode when not supplied, else honored verbatim (a
 * crafted message may lie); the body is bounded by Data Length and the captured bytes so a pipelined /
 * trailing message is left to the codec's recursion / RawData. Reserved is honored verbatim. A
 * well-formed message round-trips byte-for-byte.
 */
export class Zabbix extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Zabbix.#schemaCache ??= Zabbix.#buildSchema())
    }

    /** A little-endian unsigned 32-bit field of 4 octets at `offset`. */
    static #fieldUInt32LE(name: string, offset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 4294967295,
            decode: function (this: Zabbix): void {
                const b: Buffer = this.readBytes(offset, 4)
                //`|` yields a signed int32, so apply `>>> 0` to the WHOLE expression to get an unsigned
                //32-bit value — otherwise a value with the high bit set decodes as a negative number.
                ;(this.instance as any)[name].setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
            },
            encode: function (this: Zabbix): void {
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > 4294967295) {
                    this.recordError(node.getPath(), 'Maximum value is 4294967295')
                    value = 4294967295
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(offset, Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff]))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Zabbix flags=${flags} len=${dataLength}',
            properties: {
                //The 4-byte protocol Magic — always "ZBXD" (0x5A425844) on the wire; kept verbatim so any
                //non-standard magic still round-trips.
                magic: this.fieldHex('magic', 0, 4, 'Magic'),
                //Flags bitfield: 0x01 ZBX_TCP_PROTOCOL (uncompressed), 0x02 ZBX_TCP_COMPRESS, 0x04
                //ZBX_TCP_LARGE. Kept as a plain uint8 (byte-perfect and editable); the bit split is UI
                //enrichment for later.
                flags: this.fieldUInt('flags', 4, 1, 'Flags'),
                dataLength: {
                    type: 'integer',
                    label: 'Data Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: Zabbix): void {
                        const b: Buffer = this.readBytes(5, 4)
                        this.instance.dataLength.setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
                    },
                    encode: function (this: Zabbix): void {
                        //Data Length counts only the body that follows the 13-byte header (LITTLE-ENDIAN).
                        //Honored when supplied (a crafted message may lie); else derived from the body.
                        const provided: number | undefined = this.instance.dataLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.dataLength.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.dataLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.dataLength.setValue(value)
                        this.writeBytes(5, Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff]))
                    }
                },
                //Reserved (LITTLE-ENDIAN): zero for an uncompressed message, the uncompressed body size
                //when the compressed flag (0x02) is set. Honored verbatim — a byte-perfect passthrough.
                reserved: this.#fieldUInt32LE('reserved', 9, 'Reserved'),
                //The body (JSON request/response, or a zlib-deflated blob when compressed), kept verbatim.
                //Bounded by Data Length (body ends at offset 13 + Data Length) and the captured bytes, so
                //trailing/pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: Zabbix): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.dataLength.getValue(0)
                        let end: number = 13 + length
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 13 ? BufferToHex(this.readBytes(13, end - 13)) : '')
                    },
                    encode: function (this: Zabbix): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(13, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'zabbix'

    public readonly name: string = 'Zabbix Protocol'

    public readonly nickname: string = 'Zabbix'

    //Well-known Zabbix server port 10051. heuristicFallback because "ZBXD" is a reliable 4-byte content
    //signature — the Zabbix server/proxy/agent/sender speak the same framing on other ports (10050 for
    //the passive agent, arbitrary sender ports), so it must also be recognized off 10051 via match().
    public readonly matchKeys: string[] = ['tcpport:10051']

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        //Zabbix rides on TCP. Require the full 13-byte header and the "ZBXD" Magic (0x5A425844) so
        //non-Zabbix traffic falls through to raw. The magic is a strong 32-bit content signature — safe
        //to match on any port; the full-header guard keeps a crafted short frame from being claimed and
        //breaking the byte-perfect body bound.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 13) return false
        return BufferToHex(this.readBytes(0, 4, true)) === '5a425844'
    }

    //A leaf header — the JSON/compressed body is application-level, cross-message state.
    public readonly demuxProducers: DemuxProducer[] = []

}
