import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt16} from '../helper/BufferToNumber'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Border Gateway Protocol (BGP-4, RFC 4271), TCP port 179. Every BGP message begins with a fixed
 * 19-byte header — a 16-byte Marker (all ones, 0xFF, in modern BGP without authentication), a 2-byte
 * Length (the total message octet count including this header), and a 1-byte Type (1 OPEN, 2 UPDATE,
 * 3 NOTIFICATION, 4 KEEPALIVE) — followed by the type-specific body.
 *
 * The body layout differs per message type (OPEN's capabilities, UPDATE's withdrawn routes / path
 * attributes / NLRI, NOTIFICATION's error code) and several sub-structures need cross-message and
 * capability-negotiation context, so this single-message codec keeps the body verbatim as `body` hex
 * (byte-perfect) and does not sub-decode it. The Length is auto-computed from the body on encode when
 * not supplied, else honored verbatim (a crafted message may lie); the message is bounded by Length so
 * a second pipelined BGP message or trailing bytes are left to the codec's recursion / RawData. A
 * well-formed message round-trips byte-for-byte.
 */
export class BGP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (BGP.#schemaCache ??= BGP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'BGP type=${type} len=${length}',
            properties: {
                //The 16-byte Marker. In RFC 4271 (no authentication) it is all ones (0xFF); kept
                //verbatim so any legacy/authenticated marker still round-trips.
                marker: this.fieldHex('marker', 0, 16, 'Marker'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 19,
                    maximum: 65535,
                    decode: function (this: BGP): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(16, 2)))
                    },
                    encode: function (this: BGP): void {
                        //Length counts the whole message = 19-byte header + body. Honored when supplied
                        //(a crafted message may lie); else derived from the body.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 19 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(16, UInt16ToBuffer(value))
                    }
                },
                type: this.fieldUInt('type', 18, 1, 'Type'),
                //The type-specific body after the 19-byte header, kept verbatim. Bounded by the message
                //Length (the message ends at offset Length) and the captured bytes, so trailing /
                //pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: BGP): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        let end: number = length
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 19 ? BufferToHex(this.readBytes(19, end - 19)) : '')
                    },
                    encode: function (this: BGP): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(19, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'bgp'

    public readonly name: string = 'Border Gateway Protocol'

    public readonly nickname: string = 'BGP'

    public readonly matchKeys: string[] = ['tcpport:179']

    public match(): boolean {
        //BGP rides on TCP port 179. Require the full 19-byte header and the all-ones Marker signature
        //(16 bytes of 0xFF) so non-BGP 179 traffic falls through to raw. The marker is a strong,
        //distinctive content signature, but selection stays port-bucketed (matchKeys) to stay
        //conservative like the other length-bounded TCP payload codecs.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 19) return false
        const marker: Buffer = this.readBytes(0, 16, true)
        for (let i: number = 0; i < 16; i++) {
            if (marker[i] !== 0xff) return false
        }
        return true
    }

    //A leaf header — the type-specific body requires per-type, capability-dependent parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
