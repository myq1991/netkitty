import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * SMB2 / SMB3 (MS-SMB2), TCP port 445. Over the Direct TCP transport (MS-SMB2 §2.1) every message is
 * framed by a 4-byte transport header — a zero byte followed by a 24-bit big-endian StreamProtocolLength
 * giving the number of SMB2 message bytes that follow — then the 64-byte SMB2 packet header, then the
 * command-specific body.
 *
 * The 64-byte SMB2 header (MS-SMB2 §2.2.1.2, the SYNC form) is: ProtocolId (the 0xFE 'S' 'M' 'B' magic),
 * StructureSize (always 64), CreditCharge, Status/ChannelSequence+Reserved, Command (0 NEGOTIATE, 1
 * SESSION_SETUP, 3 TREE_CONNECT, 5 CREATE, 8 READ, 9 WRITE, …), CreditRequest/Response, Flags, NextCommand,
 * MessageId, Reserved(ProcessId), TreeId, SessionId and a 16-byte Signature.
 *
 * ⚠️ Every multi-byte scalar in the SMB2 header is LITTLE-ENDIAN (SMB's on-wire byte order). There is no
 * little-endian helper in this codebase, so the uint16 / uint32 fields are read and written byte-by-byte
 * in their closures. The 8-byte MessageId / SessionId and the Signature are kept verbatim as hex (opaque,
 * and 64-bit values exceed a JS number's exact integer range), so they round-trip byte-for-byte.
 *
 * The command-specific body (the NEGOTIATE dialects, SESSION_SETUP security blob, CREATE contexts, READ /
 * WRITE data, …) is cross-message, command-dependent state, so this single-message codec keeps it verbatim
 * as `body` hex (byte-perfect). The StreamProtocolLength is honored when supplied (a crafted frame may lie)
 * else derived as 64 + body bytes; the message is bounded by it, so a second compounded/pipelined message
 * or trailing bytes are left to the codec's recursion / RawData. A well-formed message round-trips
 * byte-for-byte.
 */
export class SMB2 extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SMB2.#schemaCache ??= SMB2.#buildSchema())
    }

    /** A little-endian unsigned 16-bit field of 2 octets at `offset`. */
    static #fieldUInt16LE(name: string, offset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 65535,
            decode: function (this: SMB2): void {
                const b: Buffer = this.readBytes(offset, 2)
                ;(this.instance as any)[name].setValue(b[0] | (b[1] << 8))
            },
            encode: function (this: SMB2): void {
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
            decode: function (this: SMB2): void {
                const b: Buffer = this.readBytes(offset, 4)
                //`|` yields a signed int32, so apply `>>> 0` to the WHOLE expression to get an unsigned
                //32-bit value — otherwise a value with the high bit set decodes as a negative number.
                ;(this.instance as any)[name].setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
            },
            encode: function (this: SMB2): void {
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
            summary: 'SMB2 command=${command} messageId=${messageId}',
            properties: {
                //Direct TCP transport header (MS-SMB2 §2.1): byte 0 is zero (the "session message" type),
                //bytes 1-3 are the 24-bit big-endian StreamProtocolLength. Kept as a plain octet so a
                //crafted non-zero type still round-trips.
                transportType: this.fieldUInt('transportType', 0, 1, 'Transport Type'),
                //24-bit big-endian length of the SMB2 message that follows (the 64-byte header + body,
                //excluding this 4-byte transport prefix). Honored when supplied (a crafted frame may lie);
                //else derived as 64 + body bytes.
                streamProtocolLength: {
                    type: 'integer',
                    label: 'Stream Protocol Length',
                    minimum: 0,
                    maximum: 16777215,
                    decode: function (this: SMB2): void {
                        const b: Buffer = this.readBytes(1, 3)
                        this.instance.streamProtocolLength.setValue((b[0] << 16) | (b[1] << 8) | b[2])
                    },
                    encode: function (this: SMB2): void {
                        const provided: number | undefined = this.instance.streamProtocolLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 64 + HexToBuffer(this.instance.body.getValue('')).length
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
                //The 4-byte ProtocolId magic — 0xFE 'S' 'M' 'B' (fe534d42). Kept verbatim so a crafted
                //magic round-trips; the match() gate enforces the real signature for selection.
                protocolId: this.fieldHex('protocolId', 4, 4, 'Protocol Id'),
                //StructureSize is always 64 on the wire (MS-SMB2 §2.2.1.1); kept as an honored LE uint so a
                //crafted value round-trips (no hard constraint that would reject a lying value on re-encode).
                structureSize: this.#fieldUInt16LE('structureSize', 8, 'Structure Size'),
                creditCharge: this.#fieldUInt16LE('creditCharge', 10, 'Credit Charge'),
                //Status (response) / ChannelSequence+Reserved (request) — a 4-byte LE field either way.
                status: this.#fieldUInt32LE('status', 12, 'Status/ChannelSequence'),
                //Command: 0 NEGOTIATE, 1 SESSION_SETUP, 2 LOGOFF, 3 TREE_CONNECT, 4 TREE_DISCONNECT, 5
                //CREATE, 6 CLOSE, 8 READ, 9 WRITE, … (kept as a plain honored uint — no enum, so an
                //unknown/crafted opcode still decodes and re-encodes).
                command: this.#fieldUInt16LE('command', 16, 'Command'),
                creditReqResp: this.#fieldUInt16LE('creditReqResp', 18, 'Credit Request/Response'),
                flags: this.#fieldUInt32LE('flags', 20, 'Flags'),
                //Offset of the next command in a compound request/response (0 = not compounded). This codec
                //decodes the first message only; a non-zero NextCommand's trailing bytes fall through to raw.
                nextCommand: this.#fieldUInt32LE('nextCommand', 24, 'Next Command'),
                //8-byte MessageId — kept verbatim as hex (opaque LE, and a 64-bit value exceeds a JS
                //number's exact integer range).
                messageId: this.fieldHex('messageId', 28, 8, 'Message Id'),
                //Reserved (ProcessId in the SYNC header; the low half of AsyncId in the ASYNC header),
                //kept verbatim so either header form round-trips byte-for-byte.
                reserved: this.fieldHex('reserved', 36, 4, 'Reserved'),
                treeId: this.#fieldUInt32LE('treeId', 40, 'Tree Id'),
                //8-byte SessionId — kept verbatim as hex (opaque LE, 64-bit).
                sessionId: this.fieldHex('sessionId', 44, 8, 'Session Id'),
                //16-byte message Signature (zero when unsigned) — kept verbatim.
                signature: this.fieldHex('signature', 52, 16, 'Signature'),
                //The command-specific body after the 64-byte header, kept verbatim. Bounded by the
                //StreamProtocolLength (the message ends at 4 + StreamProtocolLength) and the captured bytes,
                //so trailing / compounded / pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SMB2): void {
                        const remaining: number = this.packet.length - this.startPos
                        const streamLength: number = this.instance.streamProtocolLength.getValue(0)
                        let end: number = 4 + streamLength
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 68 ? BufferToHex(this.readBytes(68, end - 68)) : '')
                    },
                    encode: function (this: SMB2): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(68, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'smb2'

    public readonly name: string = 'SMB2'

    public readonly nickname: string = 'SMB2'

    public readonly matchKeys: string[] = ['tcpport:445']

    public match(): boolean {
        //SMB2 rides on TCP port 445 (selected via the tcpport:445 bucket). Require the 4-byte transport
        //prefix + the 0xFE 'S' 'M' 'B' (fe534d42) ProtocolId magic at offset 4 — a strong 4-byte content
        //signature — so non-SMB2 445 traffic (and legacy SMB1's 0xFF 'S' 'M' 'B') falls through to raw.
        //Selection stays port-bucketed (matchKeys, no heuristicFallback) like the other length-bounded
        //TCP payload codecs.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 8) return false
        return BufferToHex(this.readBytes(4, 4)) === 'fe534d42'
    }

    //A leaf header — the command-specific body requires per-command, cross-message parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
