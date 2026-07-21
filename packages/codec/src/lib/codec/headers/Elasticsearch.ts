import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Elasticsearch transport protocol (internal node-to-node cluster traffic), TCP port 9300. Every
 * transport message begins with a fixed prefix — the two ASCII bytes 'ES' (0x4553), a 4-byte
 * big-endian Message Length (the count of bytes that follow the Length field: Request Id + Status +
 * Version + the variable header + body), an 8-byte Request Id echoed between request and response, a
 * 1-byte Status bitfield (bit0 request/response, bit1 error, bit2 compressed) and a 4-byte Version —
 * followed by the message body (the variable header — feature set / action name — plus the serialized
 * request or response object).
 *
 * The body layout is version-, action- and compression-dependent (StreamInput/StreamOutput vInt/vLong
 * framing, optional DEFLATE, the action-specific TransportRequest/TransportResponse), so this
 * single-message codec keeps it verbatim as `body` hex (byte-perfect) and does not sub-decode it. The
 * Message Length is auto-computed from the fixed fields + body on encode when not supplied, else
 * honored verbatim (a crafted message may lie); the message is bounded by the Length (total = 6 +
 * messageLength) so a second pipelined message or trailing bytes are left to the codec's recursion /
 * RawData. A well-formed message round-trips byte-for-byte.
 */
export class Elasticsearch extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Elasticsearch.#schemaCache ??= Elasticsearch.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Elasticsearch reqId=${requestId} len=${messageLength}',
            properties: {
                //The 'ES' magic (0x4553) — kept verbatim as hex so any prefix still round-trips.
                magic: this.fieldHex('magic', 0, 2, 'Magic'),
                messageLength: {
                    type: 'integer',
                    label: 'Message Length',
                    //Wire field: never constrain below the true lower bound. A truncated/crafted message
                    //may decode any value in [0, 0xffffffff]; keep the full uint32 range so a decoded
                    //value always re-encodes (clamped in the closure, never rejected by Ajv).
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: Elasticsearch): void {
                        this.instance.messageLength.setValue(BufferToUInt32(this.readBytes(2, 4)))
                    },
                    encode: function (this: Elasticsearch): void {
                        //Length counts everything after the Length field = requestId(8) + status(1) +
                        //version(4) + body = 13 + body bytes. Honored when supplied (a crafted message
                        //may lie); else derived from the body.
                        const provided: number | undefined = this.instance.messageLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 13 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.messageLength.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.messageLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.messageLength.setValue(value)
                        this.writeBytes(2, UInt32ToBuffer(value))
                    }
                },
                //An 8-byte correlation id (a Java long) matched across a request/response pair; opaque,
                //kept verbatim so any value round-trips (no JS-number precision loss on 64 bits).
                requestId: this.fieldHex('requestId', 6, 8, 'Request Id'),
                //Status bitfield (bit0 request=0/response=1, bit1 error, bit2 compressed, bit3 handshake).
                //Kept as a plain uint8 — byte-perfect and editable; the bit split is UI enrichment for later.
                status: this.fieldUInt('status', 14, 1, 'Status'),
                //Transport protocol version (an Elasticsearch internal version id).
                version: this.fieldUInt('version', 15, 4, 'Version'),
                //The variable header + serialized request/response body, kept verbatim. Bounded by the
                //Message Length (message ends at offset 6 + messageLength) and the captured bytes, so
                //trailing / pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: Elasticsearch): void {
                        const remaining: number = this.packet.length - this.startPos
                        const messageLength: number = this.instance.messageLength.getValue(0)
                        let end: number = 6 + messageLength
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 19 ? BufferToHex(this.readBytes(19, end - 19)) : '')
                    },
                    encode: function (this: Elasticsearch): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(19, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'elasticsearch'

    public readonly name: string = 'Elasticsearch Transport'

    public readonly nickname: string = 'Elasticsearch'

    public readonly matchKeys: string[] = ['tcpport:9300']

    public match(): boolean {
        //Elasticsearch transport rides on TCP port 9300. The 'ES' magic (0x4553) is only a 2-byte
        //signature — too weak to claim traffic on any port — so selection stays port-bucketed
        //(matchKeys) and the magic is an additional guard here. Require the full 19-byte fixed header
        //(magic + length + requestId + status + version) so a short frame does not break byte-perfect
        //round-trip, and reject a 9300 payload that is not 'ES' (falls through to raw).
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 19) return false
        const magic: Buffer = this.readBytes(0, 2, true)
        return magic[0] === 0x45 && magic[1] === 0x53
    }

    //A leaf header — the body requires version/action/compression-dependent StreamInput parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
