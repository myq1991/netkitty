import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * MySQL client/server protocol (MySQL / MariaDB wire protocol), TCP port 3306. Every message is framed by
 * a 4-byte packet header — a 3-byte payload length followed by a 1-byte sequence id — then exactly
 * `payloadLength` bytes of payload. The payload's meaning is connection-phase- and command-dependent
 * (handshake, auth, command, resultset) and is cross-message stateful, so this single-message codec
 * structures only the 4-byte packet header and keeps the payload verbatim as `payload` hex (byte-perfect).
 *
 * ⚠️ Unlike most of the codec's protocols, the 3-byte payload length is LITTLE-ENDIAN (the MySQL wire
 * protocol is little-endian throughout). There is no little-endian helper in this codebase, so the length
 * is read and written byte-by-byte in its closure: `b[0] | (b[1] << 8) | (b[2] << 16)` (max 0xFFFFFF, so
 * no sign issue — the value is always < 2^24). See ENIP.ts for the same hand-written little-endian pattern.
 *
 * The payload is bounded by the length field (it ends at offset 4 + payloadLength) and by the captured
 * bytes, so a pipelined second MySQL packet or trailing bytes in the same segment are left to the codec's
 * recursion / RawData. The length is auto-computed from the payload on encode when not supplied, else
 * honored verbatim (a crafted message may carry any length). A well-formed message round-trips byte-for-byte.
 */
export class MySQL extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (MySQL.#schemaCache ??= MySQL.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'MySQL seq=${sequenceId} len=${payloadLength}',
            properties: {
                //The 3-byte payload length is LITTLE-ENDIAN (MySQL wire byte order); read/written by hand.
                payloadLength: {
                    type: 'integer',
                    label: 'Payload Length',
                    minimum: 0,
                    maximum: 0xffffff,
                    decode: function (this: MySQL): void {
                        const b: Buffer = this.readBytes(0, 3)
                        this.instance.payloadLength.setValue(b[0] | (b[1] << 8) | (b[2] << 16))
                    },
                    encode: function (this: MySQL): void {
                        //The length counts only the payload that follows the 4-byte packet header.
                        //Honored when supplied (a crafted message may lie); else derived from the payload.
                        const provided: number | undefined = this.instance.payloadLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.payload.getValue('')).length
                        if (value > 0xffffff) {
                            this.recordError(this.instance.payloadLength.getPath(), 'Maximum value is 16777215')
                            value = 0xffffff
                        }
                        if (value < 0) {
                            this.recordError(this.instance.payloadLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.payloadLength.setValue(value)
                        //3-byte little-endian: low byte first. value < 2^24, so value >> 16 is a plain
                        //non-negative byte — no sign issue.
                        this.writeBytes(0, Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff]))
                    }
                },
                sequenceId: this.fieldUInt('sequenceId', 3, 1, 'Sequence ID'),
                //The message payload after the 4-byte packet header, kept verbatim. Bounded by the length
                //field (the message ends at offset 4 + payloadLength) and the captured bytes, so a pipelined
                //second packet or trailing bytes are left to the codec's recursion / RawData.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: MySQL): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.payloadLength.getValue(0)
                        let end: number = 4 + length
                        if (end > remaining) end = remaining
                        this.instance.payload.setValue(end > 4 ? BufferToHex(this.readBytes(4, end - 4)) : '')
                    },
                    encode: function (this: MySQL): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(4, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'mysql'

    public readonly name: string = 'MySQL Protocol'

    public readonly nickname: string = 'MySQL'

    //MySQL is recognized ONLY on its well-known port bucket (tcp:3306) — deliberately NOT via
    //heuristicFallback. The 4-byte packet header (a 3-byte length + a sequence id) carries no reliable
    //mid-stream content signature: any TCP segment could begin with a plausible little-endian length, so a
    //global heuristic would mislabel unrelated traffic as MySQL. Confining MySQL to its tcp:3306 bucket (as
    //FTP/SMTP/POP3 are confined to theirs) keeps that collision impossible; alt-port MySQL is rare and
    //falls losslessly to raw.
    public readonly matchKeys: string[] = ['tcpport:3306']

    public match(): boolean {
        //MySQL rides on TCP port 3306. The packet header carries no strong content magic, so the
        //well-known port is the signature: require at least the full 4-byte packet header to be present.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        return this.packet.length - this.startPos >= 4
    }

    //A leaf header — the payload is phase/command-dependent, cross-message state; kept as hex, not demuxed.
    public readonly demuxProducers: DemuxProducer[] = []

}
