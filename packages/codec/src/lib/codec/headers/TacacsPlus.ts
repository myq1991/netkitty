import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * TACACS+ — Terminal Access Controller Access-Control System Plus (RFC 8907), a Cisco AAA protocol on
 * TCP port 49. Every packet begins with a 12-byte big-endian header: a Version octet split into a
 * major (high nibble, 0xc for TACACS+) and minor (low nibble) version, a Type (1 Authentication,
 * 2 Authorization, 3 Accounting), a Sequence Number, a Flags octet (bit0 UNENCRYPTED_FLAG,
 * bit2 SINGLE_CONNECT_FLAG), a 32-bit Session Id, and a 32-bit Length counting the body that follows.
 *
 * The body is almost always obfuscated (XOR-encrypted with the shared secret and a hash of the header
 * fields), and recovering it is cross-packet, key-dependent state — so this single-packet codec keeps
 * the body verbatim as `body` hex and does not sub-decode it. The Length is auto-computed from the body
 * on encode when not supplied, else honored verbatim (a crafted packet may lie); the body is bounded by
 * the Length-derived extent and the captured bytes, so a pipelined/trailing packet is left to RawData.
 * A well-formed packet round-trips byte-for-byte.
 */
export class TacacsPlus extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (TacacsPlus.#schemaCache ??= TacacsPlus.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'TACACS+ type=${type} session=${sessionId}',
            properties: {
                //Version octet (byte 0, MSB first): major version (high nibble) + minor version (low nibble).
                version: {
                    type: 'object',
                    label: 'Version',
                    properties: {
                        major: {
                            type: 'integer',
                            label: 'Major Version',
                            minimum: 0,
                            maximum: 15,
                            decode: function (this: TacacsPlus): void { this.instance.version.major.setValue(this.readBits(0, 1, 0, 4)) },
                            encode: function (this: TacacsPlus): void { this.writeBits(0, 1, 0, 4, this.instance.version.major.getValue(0)) }
                        },
                        minor: {
                            type: 'integer',
                            label: 'Minor Version',
                            minimum: 0,
                            maximum: 15,
                            decode: function (this: TacacsPlus): void { this.instance.version.minor.setValue(this.readBits(0, 1, 4, 4)) },
                            encode: function (this: TacacsPlus): void { this.writeBits(0, 1, 4, 4, this.instance.version.minor.getValue(0)) }
                        }
                    }
                },
                type: this.fieldUInt('type', 1, 1, 'Type'),
                seqNo: this.fieldUInt('seqNo', 2, 1, 'Sequence Number'),
                flags: this.fieldUInt('flags', 3, 1, 'Flags'),
                sessionId: this.fieldUInt('sessionId', 4, 4, 'Session Id'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: TacacsPlus): void {
                        this.instance.length.setValue(BufferToUInt32(this.readBytes(8, 4)))
                    },
                    encode: function (this: TacacsPlus): void {
                        //Length counts only the body that follows the 12-byte header. Honored when supplied
                        //(a crafted packet may lie); else derived from the body. TACACS+ is big-endian, so
                        //UInt32ToBuffer (BE) is used directly — no hand little-endian assembly.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(8, UInt32ToBuffer(value))
                    }
                },
                //The body after the 12-byte header, kept verbatim (usually encrypted). Bounded by the
                //Length field (the packet ends at offset 12 + Length) and the captured bytes, so trailing
                //or pipelined data is not absorbed.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: TacacsPlus): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        let end: number = 12 + length
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 12 ? BufferToHex(this.readBytes(12, end - 12)) : '')
                    },
                    encode: function (this: TacacsPlus): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(12, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'tacacs'

    public readonly name: string = 'TACACS+'

    public readonly nickname: string = 'TACACS+'

    public readonly matchKeys: string[] = ['tcpport:49']

    public match(): boolean {
        //TACACS+ rides on TCP port 49. Require the 12-byte header and the 0xc major-version nibble (the
        //TACACS+ signature) so non-TACACS+ port-49 traffic falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 12) return false
        const byte0: number = this.readBytes(0, 1, true)[0]
        return (byte0 >> 4) === 0xc
    }

    //A leaf header — the body is usually encrypted and is kept as hex, not demuxed further.
    public readonly demuxProducers: DemuxProducer[] = []

}
