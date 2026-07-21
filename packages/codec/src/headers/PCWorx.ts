import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt16} from '../helper/BufferToNumber'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * PCWorx (Phoenix Contact ILC / AXC classic PLC engineering protocol), TCP port 1962. There is no
 * public authoritative specification for PCWorx; the on-wire framing used here is reverse-engineered
 * from the Digital Bond "Redpoint" pcworx-info.nse scanner and the OpenVAS "PCWorx Detection (TCP)"
 * probe, which agree on a fixed 4-byte message header:
 *
 *   offset 0  opcode   (1 byte)  — leading message opcode; 0x01 in every observed PCWorx frame
 *   offset 1  service  (1 byte)  — service / sequence byte. Requests use small values (Redpoint's
 *                                  three-step probe sends 0x01, 0x05, 0x06); a response sets the high
 *                                  bit (the scanner validates a reply by testing this byte == 0x81).
 *   offset 2  length   (2 bytes, big-endian) — the TOTAL message length in octets INCLUDING this
 *                                  4-byte header (verified on Redpoint's requests: 0x001a=26 = 4+22,
 *                                  0x0016=22 = 4+18, 0x000e=14 = 4+10).
 *
 * followed by `length - 4` bytes of opcode/service-specific body (session id, string-table indices,
 * null-terminated PLC-type / firmware / model strings — all cross-message, session-stateful, and not
 * publicly documented). This single-message codec therefore keeps the body verbatim as `body` hex
 * (byte-perfect) and does not sub-decode it. The Length is auto-computed (4 + body) on encode when not
 * supplied, else honored verbatim (a crafted message may lie); the message is bounded by Length so a
 * pipelined/trailing message is left to the codec's recursion / RawData. A well-formed message
 * round-trips byte-for-byte.
 */
export class PCWorx extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (PCWorx.#schemaCache ??= PCWorx.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'PCWorx op=${opcode} svc=${service} len=${length}',
            properties: {
                //Leading message opcode (0x01 in every observed PCWorx frame). Kept as a plain uint8
                //(no enum) so any on-wire value still decodes and re-encodes.
                opcode: this.fieldUInt('opcode', 0, 1, 'Opcode'),
                //Service / sequence byte. Requests carry small values; a response sets the high bit
                //(0x81). Kept as a plain uint8 so both directions round-trip.
                service: this.fieldUInt('service', 1, 1, 'Service'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: PCWorx): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: PCWorx): void {
                        //Length counts the WHOLE message = 4-byte header + body. Honored when supplied
                        //(a crafted message may lie); else derived from the body.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 4 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(2, UInt16ToBuffer(value))
                    }
                },
                //The opcode/service-specific body after the 4-byte header, kept verbatim. Bounded by the
                //message Length (the message ends at offset Length) and the captured bytes, so trailing /
                //pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: PCWorx): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        let end: number = length
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 4 ? BufferToHex(this.readBytes(4, end - 4)) : '')
                    },
                    encode: function (this: PCWorx): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(4, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'pcworx'

    public readonly name: string = 'PCWorx'

    public readonly nickname: string = 'PCWorx'

    public readonly matchKeys: string[] = ['tcpport:1962']

    public match(): boolean {
        //PCWorx rides on TCP port 1962. The 4-byte header carries no strong content magic (opcode is
        //0x01 but that is far too weak to key on off-port), so the well-known port is the signature:
        //require the full 4-byte header to be present so a too-short segment falls through to raw.
        //Selection stays port-bucketed (matchKeys) like the other length-bounded TCP payload codecs;
        //no heuristicFallback.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        return this.packet.length - this.startPos >= 4
    }

    //A leaf header — the body is session-stateful and not publicly specified; kept as hex, not demuxed.
    public readonly demuxProducers: DemuxProducer[] = []

}
