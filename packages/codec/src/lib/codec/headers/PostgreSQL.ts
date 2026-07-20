import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * The PostgreSQL v3 message-type bytes (a single ASCII byte that opens every TYPED message). Frontend and
 * backend share the byte space: e.g. Q Query, P Parse, B Bind, E Execute/ErrorResponse, C Close/
 * CommandComplete, D Describe/DataRow, R Authentication, Z ReadyForQuery, T RowDescription, S Sync/
 * ParameterStatus, K BackendKeyData, X Terminate, plus the digit types 1/2/3 (Parse/Bind/CloseComplete).
 * Used by match() and by decode's typed-vs-startup discriminator — a startup message has NO type byte (see
 * the class doc), so its first byte is the high octet of a (small) length, never one of these letters.
 */
const PG_MESSAGE_TYPES: string = 'ABCDEFGHIKNPQRSTVWXZcdfnpstvw123'

/** PostgreSQL v3 protocol-version MAJOR number (the high 16 bits of the startup version word: 0x0003xxxx). */
const PG_PROTOCOL_MAJOR_V3: number = 0x0003

/**
 * The special startup request codes that appear in place of a protocol version: SSLRequest (80877103 =
 * 0x04d2162f), CancelRequest (80877102 = 0x04d2162e) and GSSENCRequest (80877104 = 0x04d21630). Like a v3
 * StartupMessage, these have no type byte — length(4) + code(4) [ + payload ].
 */
const PG_SPECIAL_REQUEST_CODES: number[] = [0x04d2162f, 0x04d2162e, 0x04d21630]

/**
 * PostgreSQL frontend/backend protocol, version 3 (the wire protocol of libpq / the `psql` client and the
 * server), carried over TCP well-known port 5432.
 *
 * Almost every message is framed uniformly: a 1-byte ASCII messageType (e.g. 'Q' Query, 'P' Parse, 'R'
 * Authentication, 'C' CommandComplete, 'D' DataRow, 'Z' ReadyForQuery, 'T' RowDescription, 'S'
 * ParameterStatus, 'E' ErrorResponse, 'K' BackendKeyData, 'X' Terminate), then a BIG-ENDIAN uint32 length,
 * then (length − 4) body bytes. Crucially the length INCLUDES its own 4 bytes but NOT the type byte, so a
 * typed message occupies 1 + length bytes on the wire and its body lives at offset 5.
 *
 * ⚠️ EXCEPTION — the very first message of a connection has NO type byte. The StartupMessage (and the
 * SSLRequest / CancelRequest / GSSENCRequest handshakes) is length(4, BE) + protocol-version-or-code(4) +
 * params: length still includes its own 4 bytes, so the body (version + params) lives at offset 4, and the
 * message occupies exactly `length` bytes. The two shapes are told apart by the first byte: a typed
 * message opens with a printable message-type letter; a startup message opens with the high octet of a
 * small length (0x00 in practice) and carries a v3 version word (0x0003xxxx) or a special request code at
 * offset 4. THIS OFFSET DIFFERENCE (typed length@1 body@5 vs startup length@0 body@4) is the crux of the
 * codec — every field closure branches on it via #isStartupDecode()/#isStartupEncode().
 *
 * Per-message-type body structure (Parse's query text + parameter OIDs, DataRow's column array, an
 * Authentication request's method, …) is message-type-specific and often cross-message (the backend's
 * reply depends on the frontend's request), so this slice keeps the body verbatim as `body` hex
 * (byte-perfect), bounded by the length field so a pipelined/trailing message is left to the codec's
 * recursion / RawData. The length is honored when supplied (a crafted message may lie), else derived as
 * 4 + body bytes. A well-formed message round-trips byte-for-byte. Structuring per-message-type bodies is
 * a later slice.
 */
export class PostgreSQL extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (PostgreSQL.#schemaCache ??= PostgreSQL.#buildSchema())
    }

    /** True when `byte` is a printable PostgreSQL v3 message-type byte (opens a TYPED message). */
    static #isTypeByte(byte: number): boolean {
        return PG_MESSAGE_TYPES.includes(String.fromCharCode(byte))
    }

    /** Bytes of this header's payload available in the segment (never negative). */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /**
     * Decide, at DECODE time, whether the message at startPos is a startup message (no type byte) vs a
     * typed message: a typed message opens with a printable message-type letter, so anything else (the
     * high octet of a small length, 0x00 in practice) is a startup message. match() gates entry to exactly
     * these two shapes, so this two-way split is reliable.
     */
    #isStartupDecode(): boolean {
        if (this.#payloadLength() < 1) return false
        return !PostgreSQL.#isTypeByte(this.readBytes(0, 1, true)[0])
    }

    /**
     * Decide, at ENCODE time, whether to emit a startup frame (no type byte). The messageType is the
     * discriminator: a typed message always carries a non-empty type byte, a startup message carries none
     * (messageType === '', the value decode stores for a startup). So an empty messageType means startup.
     */
    #isStartupEncode(): boolean {
        return this.instance.messageType.getValue('') === ''
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'PostgreSQL ${messageType}',
            properties: {
                //Display-only flag: is this the type-byte-less startup/handshake message? Set on decode
                //from the first byte; has no encode of its own (encode derives the framing from
                //messageType emptiness — see #isStartupEncode), so it never affects the re-emitted bytes.
                isStartup: {
                    type: 'boolean',
                    label: 'Is Startup',
                    decode: function (this: PostgreSQL): void {
                        this.instance.isStartup.setValue(this.#isStartupDecode())
                    }
                },
                //The 1-byte ASCII message type ('' for a startup message, which has no type byte). Decode
                //reads it only for a typed message; encode writes exactly 1 byte for a typed message and
                //nothing for a startup message, so both shapes round-trip byte-for-byte.
                messageType: {
                    type: 'string',
                    label: 'Message Type',
                    maxLength: 1,
                    contentEncoding: StringContentEncodingEnum.ASCII,
                    decode: function (this: PostgreSQL): void {
                        this.instance.messageType.setValue(this.#isStartupDecode() ? '' : this.readBytes(0, 1).toString('latin1'))
                    },
                    encode: function (this: PostgreSQL): void {
                        const value: string = this.instance.messageType.getValue('')
                        //Empty ⇒ startup message: no type byte is written (the length is the first field).
                        if (value === '') return
                        const buffer: Buffer = Buffer.alloc(1)
                        Buffer.from(value, 'latin1').copy(buffer, 0, 0, 1)
                        this.writeBytes(0, buffer)
                    }
                },
                //BIG-ENDIAN uint32 length. It INCLUDES its own 4 bytes but NOT the type byte, so it lives
                //at offset 1 for a typed message and at offset 0 for a startup message. Honored when
                //supplied (a crafted message may lie); else derived as 4 (the length word) + body bytes.
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: PostgreSQL): void {
                        const offset: number = this.#isStartupDecode() ? 0 : 1
                        this.instance.length.setValue(BufferToUInt32(this.readBytes(offset, 4)))
                    },
                    encode: function (this: PostgreSQL): void {
                        const startup: boolean = this.#isStartupEncode()
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 4 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(startup ? 0 : 1, UInt32ToBuffer(value))
                    }
                },
                //The message body after the length word, kept verbatim. For a TYPED message the body is at
                //offset 5 (type byte + 4 length bytes) and the message ends at 1 + length; for a STARTUP
                //message the body (version/code + params) is at offset 4 and the message ends at length.
                //Bounded by the length field and the captured bytes, so trailing/pipelined data is left to
                //the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: PostgreSQL): void {
                        const remaining: number = this.#payloadLength()
                        const startup: boolean = this.#isStartupDecode()
                        const headerLen: number = startup ? 4 : 5
                        const length: number = this.instance.length.getValue(0)
                        //Wire span of the whole message: startup = length; typed = 1 (type) + length.
                        let end: number = startup ? length : 1 + length
                        if (end > remaining) end = remaining
                        if (end < headerLen) end = headerLen
                        this.instance.body.setValue(end > headerLen ? BufferToHex(this.readBytes(headerLen, end - headerLen)) : '')
                    },
                    encode: function (this: PostgreSQL): void {
                        const headerLen: number = this.#isStartupEncode() ? 4 : 5
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(headerLen, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'pgsql'

    public readonly name: string = 'PostgreSQL Protocol'

    public readonly nickname: string = 'PostgreSQL'

    //PostgreSQL is recognized ONLY on its well-known port bucket 5432 — deliberately NOT via
    //heuristicFallback. The v3 framing has NO strong global signature: a typed message is just a single
    //ASCII letter followed by a 4-byte length, and a startup message is a small length followed by a
    //version word — both are byte patterns that ordinary text or binary streams reproduce constantly, so
    //(like POP3 and Redis, whose 1-byte/verb signatures are equally weak) joining the global heuristic
    //chain would let PostgreSQL mis-claim countless non-PG layers on any port. Confining it to the
    //tcp:5432 bucket makes that impossible off-port; alt-port PostgreSQL is rare and falls losslessly to
    //raw.
    public readonly matchKeys: string[] = ['tcpport:5432']

    public match(): boolean {
        //PostgreSQL rides on TCP port 5432. Within that bucket, confirm one of the two v3 shapes so
        //non-PG traffic on 5432 falls through to raw:
        //  • a TYPED message — a known message-type letter followed by a plausible 4-byte length; or
        //  • a STARTUP message — a small length (8..296) whose next 4 bytes are a v3 version word
        //    (0x0003xxxx) or a special request code (SSLRequest / CancelRequest / GSSENCRequest).
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        //Need at least a type byte + a 4-byte length (typed), which is also enough for a startup's
        //length + the start of its version word.
        if (this.#payloadLength() < 5) return false
        const first: number = this.readBytes(0, 1, true)[0]
        if (PostgreSQL.#isTypeByte(first)) {
            //Typed message: length includes its own 4 bytes, so a sane length is >= 4 and not absurd
            //(PostgreSQL caps a message at ~1 GiB).
            const length: number = BufferToUInt32(this.readBytes(1, 4, true))
            return length >= 4 && length <= 0x3fffffff
        }
        //Startup message: length(4) + version-or-code(4). Require the full 8 bytes and a plausible,
        //bounded length, then a v3 version word or a recognized special request code.
        if (this.#payloadLength() < 8) return false
        const length: number = BufferToUInt32(this.readBytes(0, 4, true))
        if (length < 8 || length > 296) return false
        const code: number = BufferToUInt32(this.readBytes(4, 4, true))
        if ((code >>> 16) === PG_PROTOCOL_MAJOR_V3) return true
        return PG_SPECIAL_REQUEST_CODES.includes(code)
    }

    //A leaf header — the per-message-type body requires message-dependent, cross-message parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
