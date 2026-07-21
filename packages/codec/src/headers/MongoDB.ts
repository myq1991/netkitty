import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * MongoDB Wire Protocol (TCP port 27017). Every message begins with a fixed 16-byte standard message
 * header — messageLength, requestID, responseTo, opCode — followed by an opCode-specific body. The
 * messageLength counts the WHOLE message including the 16-byte header; requestID / responseTo tie a
 * request to its reply; opCode selects the body layout (2013 OP_MSG — the modern, general-purpose
 * message; 2004 OP_QUERY and 1 OP_REPLY — the legacy request/reply pair; plus OP_UPDATE/INSERT/… ).
 *
 * ⚠️ Every multi-byte field in the MongoDB wire protocol is LITTLE-ENDIAN. There is no little-endian
 * helper in this codebase, so the four uint32 header fields are read and written byte-by-byte in their
 * closures (`|` yields a signed int32, so the read applies `>>> 0` to the whole expression to keep a
 * high-bit-set value unsigned).
 *
 * The body layout differs per opCode (OP_MSG's flagBits + sections of BSON, OP_QUERY's collection name /
 * query document, OP_REPLY's cursor + returned documents) and BSON sub-parsing is cross-message,
 * opCode-dependent state, so this single-message codec keeps the body verbatim as `body` hex
 * (byte-perfect) and does not sub-decode it. The messageLength is auto-computed from the body on encode
 * when not supplied, else honored verbatim (a crafted message may lie); the message is bounded by
 * messageLength so a second pipelined message or trailing bytes are left to the codec's recursion /
 * RawData. A well-formed message round-trips byte-for-byte.
 */
export class MongoDB extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (MongoDB.#schemaCache ??= MongoDB.#buildSchema())
    }

    /** A little-endian unsigned 32-bit field of 4 octets at `offset` (MongoDB on-wire byte order). */
    static #fieldUInt32LE(name: string, offset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 4294967295,
            decode: function (this: MongoDB): void {
                const b: Buffer = this.readBytes(offset, 4)
                //`|` yields a signed int32, so apply `>>> 0` to the WHOLE expression to get an unsigned
                //32-bit value — otherwise a value with the high bit set decodes as a negative number.
                ;(this.instance as any)[name].setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
            },
            encode: function (this: MongoDB): void {
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
            summary: 'MongoDB opCode=${opCode} len=${messageLength}',
            properties: {
                //All multi-byte fields are LITTLE-ENDIAN.
                //messageLength counts the WHOLE message including this 16-byte header. Honored when
                //supplied (a crafted message may lie); else derived from the header + body byte length.
                messageLength: {
                    type: 'integer',
                    label: 'Message Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: MongoDB): void {
                        const b: Buffer = this.readBytes(0, 4)
                        this.instance.messageLength.setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
                    },
                    encode: function (this: MongoDB): void {
                        const provided: number | undefined = this.instance.messageLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 16 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.messageLength.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.messageLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.messageLength.setValue(value)
                        this.writeBytes(0, Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff]))
                    }
                },
                requestID: this.#fieldUInt32LE('requestID', 4, 'Request ID'),
                responseTo: this.#fieldUInt32LE('responseTo', 8, 'Response To'),
                //opCode selects the body layout (2013 OP_MSG, 2004 OP_QUERY, 1 OP_REPLY, …). Kept as a
                //plain little-endian uint32 — byte-perfect and editable; an unknown/crafted opCode is a
                //valid packet, so no enum constraint is imposed (it would reject a legal decoded value).
                opCode: this.#fieldUInt32LE('opCode', 12, 'Op Code'),
                //The opCode-specific body after the 16-byte header, kept verbatim. Bounded by the message
                //messageLength (the message ends at offset messageLength) and the captured bytes, so
                //trailing / pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: MongoDB): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.messageLength.getValue(0)
                        let end: number = length
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 16 ? BufferToHex(this.readBytes(16, end - 16)) : '')
                    },
                    encode: function (this: MongoDB): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(16, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'mongodb'

    public readonly name: string = 'MongoDB Wire Protocol'

    public readonly nickname: string = 'MongoDB'

    public readonly matchKeys: string[] = ['tcpport:27017']

    public match(): boolean {
        //MongoDB rides on TCP port 27017. The standard message header carries no strong content magic
        //(the fields are counters / an opCode), so the well-known port is the signature: require the
        //full 16-byte header to be present.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        return this.packet.length - this.startPos >= 16
    }

    //A leaf header — the opCode-specific body (BSON sections/documents) requires cross-message,
    //opCode-dependent parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
