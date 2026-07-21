import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * SMB1 / CIFS (MS-CIFS / MS-SMB), TCP port 445 (Direct TCP) and TCP port 139 (over NBSS). Both transports
 * frame the SMB message with a 4-byte prefix: a zero "session message" type byte followed by a 24-bit
 * big-endian length giving the number of SMB message bytes that follow — the Direct TCP transport header
 * (MS-SMB2 §2.1) on 445, and the equivalent NetBIOS Session Service session-message header on 139. The
 * prefix is kept structurally so a message on either port round-trips byte-for-byte.
 *
 * After the prefix comes the 32-byte SMB1 header (MS-CIFS §2.2.3.1): Protocol (the 0xFF 'S' 'M' 'B' magic,
 * ff534d42), Command (1 byte — 0x72 NEGOTIATE, 0x73 SESSION_SETUP_ANDX, 0x75 TREE_CONNECT_ANDX, …), a
 * 4-byte NT Status, Flags (1 byte), Flags2 (2 bytes), PIDHigh (2 bytes), an 8-byte SecuritySignature,
 * 2 reserved bytes, TID / PIDLow / UID / MID (2 bytes each). The parameter/data block follows: WordCount
 * (1 byte), the Words (WordCount × 2 bytes), ByteCount (2 bytes) and the Bytes.
 *
 * ⚠️ Every multi-byte scalar in the SMB1 header is LITTLE-ENDIAN (SMB's on-wire byte order). There is no
 * little-endian helper in this codebase, so the uint16 / uint32 fields are read and written byte-by-byte
 * in their closures. The 8-byte SecuritySignature and the 2-byte Reserved field are kept verbatim as hex
 * (opaque), so they round-trip byte-for-byte.
 *
 * The parameter/data block (WordCount + Words + ByteCount + Bytes) is command-dependent, cross-message
 * state, so this single-message codec keeps it verbatim as `body` hex (byte-perfect). The 24-bit prefix
 * length is honored when supplied (a crafted frame may lie) else derived as 32 + body bytes; the message
 * is bounded by it, so a second pipelined message or trailing bytes are left to the codec's recursion /
 * RawData. A well-formed message round-trips byte-for-byte.
 */
export class SMB1 extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SMB1.#schemaCache ??= SMB1.#buildSchema())
    }

    /** A little-endian unsigned 16-bit field of 2 octets at `offset`. */
    static #fieldUInt16LE(name: string, offset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 65535,
            decode: function (this: SMB1): void {
                const b: Buffer = this.readBytes(offset, 2)
                ;(this.instance as any)[name].setValue(b[0] | (b[1] << 8))
            },
            encode: function (this: SMB1): void {
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > 65535) {
                    this.recordError(node.getPath(), 'Maximum value is 65535')
                    value = 65535
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(offset, Buffer.from([value & 0xff, (value >> 8) & 0xff]))
            }
        }
    }

    /** A little-endian unsigned 32-bit field of 4 octets at `offset`. */
    static #fieldUInt32LE(name: string, offset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 4294967295,
            decode: function (this: SMB1): void {
                const b: Buffer = this.readBytes(offset, 4)
                //`|` yields a signed int32, so apply `>>> 0` to the WHOLE expression to get an unsigned
                //32-bit value — otherwise a value with the high bit set decodes as a negative number.
                ;(this.instance as any)[name].setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
            },
            encode: function (this: SMB1): void {
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
            summary: 'SMB1 command=${command} tid=${tid} mid=${mid}',
            properties: {
                //Transport prefix: byte 0 is the zero "session message" type (Direct TCP on 445, or the
                //NetBIOS Session Service session-message header on 139); bytes 1-3 are the 24-bit
                //big-endian message length. Kept as a plain octet so a crafted non-zero type round-trips.
                transportType: this.fieldUInt('transportType', 0, 1, 'Transport Type'),
                //24-bit big-endian length of the SMB message that follows (the 32-byte header + body,
                //excluding this 4-byte transport prefix). Honored when supplied (a crafted frame may lie);
                //else derived as 32 + body bytes.
                streamProtocolLength: {
                    type: 'integer',
                    label: 'Stream Protocol Length',
                    minimum: 0,
                    maximum: 16777215,
                    decode: function (this: SMB1): void {
                        const b: Buffer = this.readBytes(1, 3)
                        this.instance.streamProtocolLength.setValue((b[0] << 16) | (b[1] << 8) | b[2])
                    },
                    encode: function (this: SMB1): void {
                        const provided: number | undefined = this.instance.streamProtocolLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 32 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 16777215) {
                            this.recordError(this.instance.streamProtocolLength.getPath(), 'Maximum value is 16777215')
                            value = 16777215
                        }
                        if (value < 0) {
                            this.recordError(this.instance.streamProtocolLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.streamProtocolLength.setValue(value)
                        this.writeBytes(1, Buffer.from([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]))
                    }
                },
                //The 4-byte Protocol magic — 0xFF 'S' 'M' 'B' (ff534d42). Kept verbatim so a crafted magic
                //round-trips; the match() gate enforces the real signature for selection (and separates
                //SMB1 from SMB2's 0xFE 'S' 'M' 'B' in the same 445/139 buckets).
                protocolId: this.fieldHex('protocolId', 4, 4, 'Protocol Id'),
                //Command (MS-CIFS §2.2.2.1): 0x72 NEGOTIATE, 0x73 SESSION_SETUP_ANDX, 0x75 TREE_CONNECT_ANDX,
                //… (kept as a plain honored uint — no enum, so an unknown/crafted opcode still round-trips).
                command: this.fieldUInt('command', 8, 1, 'Command'),
                //NT Status (4-byte LE) — MS-CIFS §2.2.3.1 (in the SMB_COM error class/code form when
                //Flags2 SMB_FLAGS2_NT_STATUS is clear; a 4-byte field either way).
                status: this.#fieldUInt32LE('status', 9, 'Status'),
                flags: this.fieldUInt('flags', 13, 1, 'Flags'),
                flags2: this.#fieldUInt16LE('flags2', 14, 'Flags2'),
                //PIDHigh — the high 2 bytes of a 32-bit Process Id.
                pidHigh: this.#fieldUInt16LE('pidHigh', 16, 'PID High'),
                //8-byte SecuritySignature (zero when unsigned) — kept verbatim.
                securitySignature: this.fieldHex('securitySignature', 18, 8, 'Security Signature'),
                //2 reserved bytes — kept verbatim so they round-trip untouched.
                reserved: this.fieldHex('reserved', 26, 2, 'Reserved'),
                tid: this.#fieldUInt16LE('tid', 28, 'Tree Id'),
                //PIDLow — the low 2 bytes of the Process Id.
                pidLow: this.#fieldUInt16LE('pidLow', 30, 'PID Low'),
                uid: this.#fieldUInt16LE('uid', 32, 'User Id'),
                mid: this.#fieldUInt16LE('mid', 34, 'Multiplex Id'),
                //The parameter/data block after the 32-byte header (WordCount + Words + ByteCount + Bytes),
                //kept verbatim. Bounded by the transport prefix length (the message ends at 4 +
                //streamProtocolLength) and the captured bytes, so trailing / pipelined data is left to the
                //codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SMB1): void {
                        const remaining: number = this.packet.length - this.startPos
                        const streamLength: number = this.instance.streamProtocolLength.getValue(0)
                        let end: number = 4 + streamLength
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 36 ? BufferToHex(this.readBytes(36, end - 36)) : '')
                    },
                    encode: function (this: SMB1): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(36, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'smb1'

    public readonly name: string = 'SMB1'

    public readonly nickname: string = 'SMB1'

    //SMB1/CIFS rides TCP port 445 (Direct TCP) and 139 (over NBSS).
    public readonly matchKeys: string[] = ['tcpport:445', 'tcpport:139']

    public match(): boolean {
        //SMB1 rides on TCP port 445 / 139 (selected via the tcpport buckets). Require the 4-byte transport
        //prefix + the 0xFF 'S' 'M' 'B' (ff534d42) Protocol magic at offset 4 — a strong 4-byte content
        //signature — so non-SMB1 445/139 traffic (and SMB2's 0xFE 'S' 'M' 'B') falls through to raw. The
        //magic gate makes SMB1 and SMB2 mutually exclusive in the shared port buckets. Selection stays
        //port-bucketed (matchKeys, no heuristicFallback) like the other length-bounded TCP payload codecs.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 8) return false
        return BufferToHex(this.readBytes(4, 4)) === 'ff534d42'
    }

    //A leaf header — the command-specific parameter/data block requires per-command, cross-message parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
