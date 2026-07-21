import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** The eight OPC UA TCP message types (IEC 62541-6). A valid message begins with one of these. */
const OPCUA_MESSAGE_TYPES: string[] = ['HEL', 'ACK', 'ERR', 'OPN', 'MSG', 'CLO', 'RHE', 'RHF']

/** The IsFinal / chunk indicator: F (final), C (intermediate chunk), A (abort). */
const OPCUA_CHUNK_TYPES: string[] = ['F', 'C', 'A']

/**
 * OPC UA Connection Protocol — the OPC UA TCP transport mapping (IEC 62541-6), TCP port 4840. Every OPC
 * UA TCP message is framed by a fixed 8-byte header: a 3-byte ASCII MessageType (HEL/ACK/ERR/OPN/MSG/
 * CLO/RHE/RHF), a 1-byte ASCII Chunk/IsFinal indicator (F final, C intermediate chunk, A abort), and a
 * LITTLE-ENDIAN uint32 MessageSize that counts the WHOLE message including the 8-byte header. The header
 * is followed by MessageSize − 8 bytes of message body.
 *
 * ⚠️ MessageSize is LITTLE-ENDIAN (the only multi-byte field in this header), and there is no
 * little-endian helper in this codebase, so it is read/written byte-by-byte in its closure. The `| ... <<`
 * expression yields a signed int32, so `>>> 0` is applied to the whole expression to keep a MessageSize
 * with the high bit set unsigned. MessageType/Chunk are ASCII text kept as strings.
 *
 * The body is message-type-dependent (HEL/ACK carry a protocol version + buffer sizes + endpoint URL;
 * OPN/MSG/CLO carry a SecureChannelId + security/sequence headers + an encoded body), and much of it is
 * cross-message / security-context state. So this single-message codec keeps the body verbatim as `body`
 * hex (byte-perfect), bounded by MessageSize (the body ends at offset MessageSize, clamped to the
 * captured bytes) so a pipelined/trailing message is left to the codec's recursion / RawData. The
 * MessageSize is honored when supplied (a crafted message may lie), else derived as 8 + body bytes. A
 * well-formed message round-trips byte-for-byte. Structuring the per-message-type body is a later slice.
 */
export class OPCUA extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (OPCUA.#schemaCache ??= OPCUA.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'OPC UA ${messageType}',
            properties: {
                //3-byte ASCII message type (HEL/ACK/ERR/OPN/MSG/CLO/RHE/RHF). Kept as a string; encode
                //writes exactly 3 bytes (a decoded value is always 3 chars; a crafted value is truncated
                //or zero-padded to 3) so a well-formed message round-trips byte-for-byte.
                messageType: {
                    type: 'string',
                    label: 'Message Type',
                    minLength: 3,
                    maxLength: 3,
                    contentEncoding: StringContentEncodingEnum.ASCII,
                    decode: function (this: OPCUA): void {
                        this.instance.messageType.setValue(this.readBytes(0, 3).toString('latin1'))
                    },
                    encode: function (this: OPCUA): void {
                        const node: any = this.instance.messageType
                        const value: string = node.getValue('', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        node.setValue(value)
                        const buffer: Buffer = Buffer.alloc(3)
                        Buffer.from(value, 'latin1').copy(buffer, 0, 0, 3)
                        this.writeBytes(0, buffer)
                    }
                },
                //1-byte ASCII chunk / IsFinal indicator (F/C/A). Kept as a string; encode writes exactly
                //1 byte.
                chunk: {
                    type: 'string',
                    label: 'Chunk',
                    minLength: 1,
                    maxLength: 1,
                    contentEncoding: StringContentEncodingEnum.ASCII,
                    decode: function (this: OPCUA): void {
                        this.instance.chunk.setValue(this.readBytes(3, 1).toString('latin1'))
                    },
                    encode: function (this: OPCUA): void {
                        const node: any = this.instance.chunk
                        const value: string = node.getValue('', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        node.setValue(value)
                        const buffer: Buffer = Buffer.alloc(1)
                        Buffer.from(value, 'latin1').copy(buffer, 0, 0, 1)
                        this.writeBytes(3, buffer)
                    }
                },
                //LITTLE-ENDIAN uint32: the total message length INCLUDING the 8-byte header. Honored when
                //supplied (a crafted message may lie); else derived as 8 + body bytes.
                messageSize: {
                    type: 'integer',
                    label: 'Message Size',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: OPCUA): void {
                        const b: Buffer = this.readBytes(4, 4)
                        //`|` yields a signed int32, so apply `>>> 0` to the WHOLE expression to get an
                        //unsigned 32-bit value — otherwise a size with the high bit set decodes negative.
                        this.instance.messageSize.setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
                    },
                    encode: function (this: OPCUA): void {
                        const provided: number | undefined = this.instance.messageSize.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 8 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.messageSize.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.messageSize.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.messageSize.setValue(value)
                        this.writeBytes(4, Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff]))
                    }
                },
                //The message body after the 8-byte header, kept verbatim. Bounded by MessageSize (the body
                //ends at offset MessageSize) and the captured bytes, so trailing/pipelined data is left to
                //the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: OPCUA): void {
                        const remaining: number = this.packet.length - this.startPos
                        const size: number = this.instance.messageSize.getValue(0)
                        let end: number = size
                        if (end < 8) end = 8
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 8 ? BufferToHex(this.readBytes(8, end - 8)) : '')
                    },
                    encode: function (this: OPCUA): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(8, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'opcua'

    public readonly name: string = 'OPC UA Connection Protocol'

    public readonly nickname: string = 'OPC UA'

    public readonly matchKeys: string[] = ['tcpport:4840']

    public match(): boolean {
        //OPC UA TCP rides on TCP port 4840. Beyond the port bucket, require the content signature: a
        //valid 3-char message type plus a valid 1-char chunk indicator — enough to separate OPC UA from
        //arbitrary port-4840 traffic. No heuristicFallback: 3+1 ASCII chars is a weaker signature than a
        //magic cookie, so this stays a port-bucket protocol (unlike STUN, whose Magic Cookie is strong
        //enough for any-port recognition).
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 8) return false
        const messageType: string = this.readBytes(0, 3, true).toString('latin1')
        if (!OPCUA_MESSAGE_TYPES.includes(messageType)) return false
        const chunk: string = this.readBytes(3, 1, true).toString('latin1')
        return OPCUA_CHUNK_TYPES.includes(chunk)
    }

    //A leaf header — the per-message-type body requires message-dependent, cross-message parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
