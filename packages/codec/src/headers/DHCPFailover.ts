import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt16} from '../helper/BufferToNumber'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * DHCP Failover protocol (ISC DHCPv4 failover, draft-ietf-dhc-failover), TCP port 647. A failover
 * connection carries a stream of messages between the primary and secondary DHCP servers. Every message
 * begins with a fixed header — a 2-byte Message Length (the total octet count of the whole message,
 * including this length field), a 1-byte Message Type (1 POOLREQ, 2 POOLRESP, 3 BNDUPD, 4 BNDACK,
 * 5 CONNECT, 6 CONNECTACK, 7 UPDREQ, 8 UPDDONE, 9 UPDREQALL, 10 STATE, 11 CONTACT, 12 DISCONNECT) —
 * followed by the rest of the message: a payload-offset byte, a time and transaction id, then a series
 * of option TLVs (2-byte option code, 2-byte option length, value).
 *
 * The payload after the Message Type is a chain of option TLVs whose meaning is message-type- and
 * cross-connection-dependent (server states, MCLT, binding status, message digests, TLS negotiation), so
 * this single-message codec keeps everything after the type verbatim as `payload` hex (byte-perfect) and
 * does not sub-decode the options. The Message Length is auto-computed from the payload on encode when
 * not supplied, else honored verbatim (a crafted message may carry any Length); the message is bounded by
 * Length so a second pipelined message or trailing bytes are left to the codec's recursion / RawData. A
 * well-formed message round-trips byte-for-byte.
 */
export class DHCPFailover extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (DHCPFailover.#schemaCache ??= DHCPFailover.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'DHCPFO type=${type} len=${length}',
            properties: {
                length: {
                    type: 'integer',
                    label: 'Message Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: DHCPFailover): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(0, 2)))
                    },
                    encode: function (this: DHCPFailover): void {
                        //Message Length counts the whole message = 2-byte length + 1-byte type + payload.
                        //Honored when supplied (a crafted message may lie); else derived from the payload.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 3 + HexToBuffer(this.instance.payload.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(0, UInt16ToBuffer(value))
                    }
                },
                type: this.fieldUInt('type', 2, 1, 'Message Type'),
                //Everything after the Message Type (payload-offset, time, xid, and the option TLVs), kept
                //verbatim. Bounded by the Message Length (the message ends at offset Length) and the
                //captured bytes, so trailing / pipelined data is left to the codec's recursion / RawData.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: DHCPFailover): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        let end: number = length
                        if (end > remaining || end < 3) end = remaining
                        this.instance.payload.setValue(end > 3 ? BufferToHex(this.readBytes(3, end - 3)) : '')
                    },
                    encode: function (this: DHCPFailover): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(3, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'dhcpfo'

    public readonly name: string = 'DHCP Failover'

    public readonly nickname: string = 'DHCPFO'

    public readonly matchKeys: string[] = ['tcpport:647']

    public match(): boolean {
        //DHCP Failover rides on TCP port 647. The message header carries no strong content magic, so the
        //well-known port is the signature. Require at least the fixed message header (2-byte length +
        //1-byte type + payload-offset + 4-byte time = 8 bytes) so tiny stray port-647 payloads fall
        //through to raw; decode itself never throws on a shorter/malformed message.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        return this.packet.length - this.startPos >= 8
    }

    //A leaf header — the option TLVs are message-type- and connection-dependent; kept as payload hex.
    public readonly demuxProducers: DemuxProducer[] = []

}
