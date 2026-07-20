import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** PPTP magic cookie (RFC 2637 §2.1): a constant 0x1A2B3C4D used to sync/verify the control channel. */
const PPTP_MAGIC_COOKIE: number = 0x1a2b3c4d

/**
 * Point-to-Point Tunnelling Protocol (PPTP, RFC 2637), TCP port 1723 — the control connection. Every
 * PPTP control message begins with a fixed 8-byte common header — a 2-byte Length (the total octet
 * count of this control message, including the header), a 2-byte PDU type (1 = control message), and a
 * 4-byte Magic Cookie (the constant 0x1A2B3C4D) — followed, for control messages, by a 2-byte Control
 * Message Type (1 Start-Control-Connection-Request, 2 …-Reply, 3 Stop-Control-Connection-Request,
 * 7 Outgoing-Call-Request, 8 …-Reply, etc.) and a 2-byte Reserved0 field, then the type-specific body.
 *
 * The body layout differs per control message type (SCCRQ's protocol version / framing & bearer
 * capabilities / host & vendor strings, Outgoing-Call's call id & bearer type, …) and several fields
 * carry negotiation context, so this single-message codec keeps the body verbatim as `body` hex
 * (byte-perfect) and does not sub-decode it. The Length is auto-computed from the structured header +
 * body on encode when not supplied, else honored verbatim (a crafted message may lie); the message is
 * bounded by Length so a second pipelined control message or trailing bytes are left to the codec's
 * recursion / RawData. The Magic Cookie is kept verbatim (honored) rather than re-derived, and the
 * Reserved0 field is preserved and re-emitted untouched. A well-formed message round-trips byte-for-byte.
 */
export class PPTP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (PPTP.#schemaCache ??= PPTP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'PPTP ctrlType=${controlMessageType} len=${length}',
            properties: {
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: PPTP): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(0, 2)))
                    },
                    encode: function (this: PPTP): void {
                        //Length counts the whole control message = 12-byte structured header
                        //(length + pduType + magicCookie + controlMessageType + reserved0) + body. Honored
                        //when supplied (a crafted message may lie); else derived from the body.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 12 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(0, UInt16ToBuffer(value))
                    }
                },
                //The PDU type (RFC 2637 §2.1). 1 = control message; this codec structures control
                //messages, the only PDU type carried on the TCP control connection.
                pduType: this.fieldUInt('pduType', 2, 2, 'PDU Type'),
                //The Magic Cookie constant 0x1A2B3C4D. Kept verbatim (honored, not re-derived) so a
                //crafted/desynced cookie still round-trips.
                magicCookie: this.fieldHex('magicCookie', 4, 4, 'Magic Cookie'),
                controlMessageType: this.fieldUInt('controlMessageType', 8, 2, 'Control Message Type'),
                //Reserved (MUST be 0 per RFC 2637); preserved and re-emitted untouched.
                reserved0: this.fieldHex('reserved0', 10, 2, 'Reserved0'),
                //The type-specific body after the 12-byte structured header, kept verbatim. Bounded by the
                //message Length (the message ends at offset Length) and the captured bytes, so trailing /
                //pipelined control messages are left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: PPTP): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        let end: number = length
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 12 ? BufferToHex(this.readBytes(12, end - 12)) : '')
                    },
                    encode: function (this: PPTP): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(12, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'pptp'

    public readonly name: string = 'Point-to-Point Tunnelling Protocol'

    public readonly nickname: string = 'PPTP'

    public readonly matchKeys: string[] = ['tcpport:1723']

    public match(): boolean {
        //PPTP's control connection rides on TCP port 1723. Require the full 12-byte structured header and
        //the Magic Cookie signature (0x1A2B3C4D at offset 4) so non-PPTP 1723 traffic falls through to
        //raw. The cookie is a strong, distinctive content signature, but selection stays port-bucketed
        //(matchKeys) to stay conservative like the other length-bounded TCP payload codecs.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 12) return false
        return BufferToUInt16(this.readBytes(4, 2, true)) === (PPTP_MAGIC_COOKIE >>> 16)
            && BufferToUInt16(this.readBytes(6, 2, true)) === (PPTP_MAGIC_COOKIE & 0xffff)
    }

    //A leaf header — the type-specific control-message body requires per-type parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
