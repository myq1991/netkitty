import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Skinny Client Control Protocol (SCCP / "Skinny", Cisco IP phone signalling), TCP port 2000. Every
 * Skinny message begins with a fixed 12-byte header — Data Length, Header Version (a reserved field,
 * conventionally 0) and Message Id — followed by the message-id-specific body. The whole message
 * occupies `8 + dataLength` bytes: the Data Length counts every byte after the Data Length and Header
 * Version fields, i.e. the 4-byte Message Id plus the body (so an empty-body KeepAlive carries
 * dataLength = 4).
 *
 * ⚠️ Like EtherNet/IP, every multi-byte Skinny field is LITTLE-ENDIAN. There is no little-endian helper
 * in this codebase, so the uint32 fields are read and written byte-by-byte in their closures (the `|`
 * expression is coerced with `>>> 0` to avoid the sign-extension of a high bit).
 *
 * The body layout differs per Message Id (0x0000 KeepAlive, 0x0001 Register, 0x0002 IpPort, 0x0003
 * KeypadButton, …) and several messages need cross-message device/call context, so this single-message
 * codec keeps the body verbatim as `body` hex (byte-perfect) and does not sub-decode it. The Data Length
 * is auto-computed from the body on encode when not supplied, else honored verbatim (a crafted message
 * may lie); the message is bounded by Data Length so a second pipelined message or trailing bytes are
 * left to the codec's recursion / RawData. A well-formed message round-trips byte-for-byte.
 */
export class Skinny extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Skinny.#schemaCache ??= Skinny.#buildSchema())
    }

    /** A little-endian unsigned 32-bit field of 4 octets at `offset`. */
    static #fieldUInt32LE(name: string, offset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 4294967295,
            decode: function (this: Skinny): void {
                const b: Buffer = this.readBytes(offset, 4)
                //`|` yields a signed int32, so apply `>>> 0` to the WHOLE expression to get an unsigned
                //32-bit value — otherwise a value with the high bit set decodes as a negative number.
                ;(this.instance as any)[name].setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
            },
            encode: function (this: Skinny): void {
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
            summary: 'Skinny msg=${messageId} len=${dataLength}',
            properties: {
                //All multi-byte Skinny fields are LITTLE-ENDIAN.
                dataLength: {
                    type: 'integer',
                    label: 'Data Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: Skinny): void {
                        const b: Buffer = this.readBytes(0, 4)
                        this.instance.dataLength.setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
                    },
                    encode: function (this: Skinny): void {
                        //Data Length counts the Message Id (4 bytes) plus the body — every byte after the
                        //Data Length and Header Version fields. Honored when supplied (a crafted message
                        //may lie); else derived from the body.
                        const provided: number | undefined = this.instance.dataLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 4 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.dataLength.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.dataLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.dataLength.setValue(value)
                        this.writeBytes(0, Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff]))
                    }
                },
                //A reserved field, conventionally 0; some builds carry a header/protocol version here.
                headerVersion: this.#fieldUInt32LE('headerVersion', 4, 'Header Version'),
                messageId: this.#fieldUInt32LE('messageId', 8, 'Message Id'),
                //The message-id-specific body after the 12-byte header, kept verbatim. Bounded by the
                //Data Length (the message ends at offset 8 + dataLength) and the captured bytes, so
                //trailing / pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: Skinny): void {
                        const remaining: number = this.packet.length - this.startPos
                        const dataLength: number = this.instance.dataLength.getValue(0)
                        let end: number = 8 + dataLength
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 12 ? BufferToHex(this.readBytes(12, end - 12)) : '')
                    },
                    encode: function (this: Skinny): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(12, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'skinny'

    public readonly name: string = 'Skinny Client Control Protocol'

    public readonly nickname: string = 'Skinny'

    public readonly matchKeys: string[] = ['tcpport:2000']

    public match(): boolean {
        //Skinny rides on TCP port 2000. The header carries no strong content magic (the Header Version
        //is conventionally 0 but not guaranteed), so the well-known port is the signature: require the
        //full 12-byte header to be present.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        return this.packet.length - this.startPos >= 12
    }

    //A leaf header — the message-id-specific body requires per-message, cross-message context parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
