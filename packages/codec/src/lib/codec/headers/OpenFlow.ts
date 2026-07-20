import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * OpenFlow (Open Networking Foundation), the SDN switch/controller protocol. Runs over TLS or plain TCP,
 * well-known port 6653 (modern; the pre-ONF IANA-assigned 6633 is still widely seen). Every OpenFlow
 * message begins with a fixed 8-byte header (big-endian) — Version (0x01 OF 1.0, 0x04 OF 1.3, 0x05 OF 1.4,
 * 0x06 OF 1.5), Type (0 Hello, 1 Error, 2 Echo Request, 3 Echo Reply, 5 Features Request, 6 Features
 * Reply, …), Length (the total message octet count INCLUDING this 8-byte header) and a Transaction ID
 * (xid, echoed on replies) — followed by the type-and-version-specific body.
 *
 * The body layout differs per Type and per Version (Error's code/data, Features Reply's datapath id and
 * port descriptions, Flow-Mod's match/instructions, …) and much of it needs cross-message negotiation
 * context, so this single-message codec keeps the body verbatim as `body` hex (byte-perfect) and does not
 * sub-decode it. Version and Type are plain uints (no hard enum) so an unknown/experimental value still
 * decodes and re-encodes. The Length is auto-computed from the body on encode when not supplied, else
 * honored verbatim (a crafted message may lie); the message is bounded by Length so a second pipelined
 * OpenFlow message or trailing bytes are left to the codec's recursion / RawData. A well-formed message
 * round-trips byte-for-byte.
 */
export class OpenFlow extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (OpenFlow.#schemaCache ??= OpenFlow.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'OpenFlow v=${version} type=${type} len=${length}',
            properties: {
                //Protocol version (0x01 OF 1.0, 0x04 OF 1.3, 0x05 OF 1.4, 0x06 OF 1.5). Kept as a plain
                //uint8 — an unknown/experimental version must still decode and round-trip, so no enum.
                version: this.fieldUInt('version', 0, 1, 'Version'),
                //Message type (0 Hello, 1 Error, 2 Echo Request, 3 Echo Reply, 5 Features Request,
                //6 Features Reply, …). Plain uint8 — versions differ in the type table, so no hard enum.
                type: this.fieldUInt('type', 1, 1, 'Type'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    //Full uint16 range: Length is honored verbatim on encode, so any on-wire value
                    //(including a crafted/short one) must re-encode without Ajv rejecting it.
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: OpenFlow): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: OpenFlow): void {
                        //Length counts the whole message = 8-byte header + body. Honored when supplied
                        //(a crafted message may lie); else derived from the body.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 8 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(2, UInt16ToBuffer(value))
                    }
                },
                //Transaction ID (xid): the sender picks it and the peer echoes it on the matching reply.
                xid: this.fieldUInt('xid', 4, 4, 'Transaction ID'),
                //The type-and-version-specific body after the 8-byte header, kept verbatim. Bounded by the
                //message Length (the message ends at offset Length) and the captured bytes, so trailing /
                //pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: OpenFlow): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        let end: number = length
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 8 ? BufferToHex(this.readBytes(8, end - 8)) : '')
                    },
                    encode: function (this: OpenFlow): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(8, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'openflow'

    public readonly name: string = 'OpenFlow'

    public readonly nickname: string = 'OpenFlow'

    public readonly matchKeys: string[] = ['tcpport:6653', 'tcpport:6633']

    public match(): boolean {
        //OpenFlow rides on TCP port 6653 (modern) / 6633 (legacy). The 8-byte header carries no strong
        //content magic (Version+Type are weak, one-byte hints), so the well-known port is the signature:
        //require the full 8-byte header to be present. Selection stays port-bucketed (matchKeys), no
        //heuristic fallback — a bare Version byte is far too weak to claim off-port traffic.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        return this.packet.length - this.startPos >= 8
    }

    //A leaf header — the body is type-and-version-specific and negotiation-dependent.
    public readonly demuxProducers: DemuxProducer[] = []

}
