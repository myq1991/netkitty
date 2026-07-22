import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * RESP type bytes → human names. The leading byte of every RESP message names its type: the RESP2 set
 * `+ - : $ *` (simple-string / error / integer / bulk-string / array) plus the RESP3 additions
 * `_ # , ( ! = % ~ >` (null / boolean / double / big-number / blob-error / verbatim-string / map / set /
 * push). Used only to label the message for display — it never affects the re-emitted bytes.
 */
const RESP_TYPES: {[byte: string]: string} = {
    '*': 'array',
    '$': 'bulk-string',
    '+': 'simple-string',
    '-': 'error',
    ':': 'integer',
    '_': 'null',
    '#': 'boolean',
    ',': 'double',
    '(': 'big-number',
    '%': 'map',
    '~': 'set',
    '>': 'push',
    '!': 'blob-error',
    '=': 'verbatim-string'
}

/** The RESP type bytes, as a lookup set for match(). A single leading byte is a WEAK signature — see matchKeys. */
const RESP_TYPE_BYTES: string = '*$+-:_#,(%~>!='

/**
 * Redis RESP — the REdis Serialization Protocol (RESP2/RESP3), carried over TCP well-known port 6379. RESP
 * is a text-ish line protocol whose FIRST byte names the message type: `+` simple string (`+OK\r\n`), `-`
 * error (`-ERR msg\r\n`), `:` integer (`:1000\r\n`), `$` bulk string (`$6\r\nfoobar\r\n`, or `$-1\r\n` null),
 * `*` array (`*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n`). RESP3 adds `_` null, `#` boolean, `,` double,
 * `(` big number, `!` blob error, `=` verbatim string, `%` map, `~` set, `>` push. Client commands are
 * almost always arrays of bulk strings (`*` framing), so the first bulk-string element is the command verb.
 *
 * Like FTP, SMTP, POP3, IMAP, Syslog, SIP and HTTP, the message is text whose full internal structure
 * (nested aggregates, binary-safe bulk strings, inline commands) is richer than a form needs. So the ENTIRE
 * raw segment is kept verbatim as the authoritative `message` field (hex) and re-emitted untouched; only a
 * little first-byte/first-line metadata is parsed on decode for display (respType/isRequest/command/preview).
 * Encode never reconstructs the message from the parsed fields — it writes `message` back byte-for-byte — so
 * any conformant (or even malformed) RESP frame round-trips exactly.
 *
 * Note: a single TCP segment may carry more than one RESP message (pipelined commands) or only part of a
 * large bulk string; reassembly across segments is out of scope. This single-segment codec keeps whatever
 * bytes are present verbatim, which is byte-perfect for the single-packet case.
 */
export class Redis extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Redis.#schemaCache ??= Redis.#buildSchema())
    }

    /**
     * Bytes of this header: RESP rides on TCP, which has no per-message length, so take the rest of the
     * segment. Reassembly across segments is out of scope (see class doc).
     */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /** The first line of the message (up to the first CRLF, or the whole payload if none). */
    static #firstLine(text: string): string {
        const idx: number = text.indexOf('\r\n')
        return idx >= 0 ? text.slice(0, idx) : text
    }

    /**
     * If the message is an array of bulk strings (RESP `*` framing, the usual client-command shape), parse
     * the FIRST bulk-string element and uppercase it — that is the Redis command verb (SET/GET/PING/AUTH/…).
     * Layout: `*<count>\r\n` then the first element `$<len>\r\n<bytes>\r\n`. Never throws: any malformed or
     * non-array/non-bulk shape yields ''. Purely display-only — it never affects the re-emitted bytes.
     */
    static #parseCommand(text: string): string {
        if (text[0] !== '*') return ''
        //Step past the `*<count>\r\n` array header.
        const arrEol: number = text.indexOf('\r\n')
        if (arrEol < 0) return ''
        //The first element must be a bulk string: `$<len>\r\n<bytes>\r\n`.
        const pos: number = arrEol + 2
        if (text[pos] !== '$') return ''
        const lenEol: number = text.indexOf('\r\n', pos)
        if (lenEol < 0) return ''
        const len: number = Number(text.slice(pos + 1, lenEol))
        if (!Number.isInteger(len) || len < 0) return ''
        const start: number = lenEol + 2
        const end: number = start + len
        if (end > text.length) return ''
        return text.slice(start, end).toUpperCase()
    }

    /**
     * Parse the leading byte / first line into the display-only metadata fields. respType names the leading
     * type byte; isRequest is the pragmatic `*`-means-client-command heuristic; command is the array's first
     * bulk string (verb); preview is the first line for display. Populated on decode only — these fields have
     * no encode, so they never affect the re-emitted bytes and never mutate `message`. Never throws:
     * empty/garbage input yields sensible defaults.
     */
    #parseMetadata(text: string): void {
        const lead: string = text.length > 0 ? text[0] : ''
        const respType: string = lead in RESP_TYPES ? RESP_TYPES[lead] : 'unknown'
        this.instance.respType.setValue(respType)
        this.instance.isRequest.setValue(lead === '*')
        this.instance.command.setValue(Redis.#parseCommand(text))
        this.instance.preview.setValue(Redis.#firstLine(text))
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Redis ${respType} ${command}',
            properties: {
                //The whole raw segment is the single source of truth: decoded verbatim to hex and re-emitted
                //untouched (byte-perfect for any RESP frame). The leading byte / first line is parsed into the
                //display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: Redis): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseMetadata('')
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseMetadata(raw.toString('latin1'))
                    },
                    encode: function (this: Redis): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed on decode (no encode — populated by the message field above,
                //never read back). respType names the leading type byte; isRequest flags the `*` array shape
                //that client commands use; command is the array's first bulk string (the verb); preview is the
                //first line as latin1 text.
                respType: {type: 'string', label: 'RESP Type'},
                isRequest: {type: 'boolean', label: 'Is Request'},
                command: {type: 'string', label: 'Command'},
                preview: {type: 'string', label: 'Preview'}
            }
        }
    }

    public readonly id: string = 'redis'

    public readonly name: string = 'Redis Serialization Protocol'

    public readonly nickname: string = 'Redis'

    //Redis is recognized ONLY on its well-known port bucket 6379 — deliberately NOT via heuristicFallback.
    //A RESP message is identified by a SINGLE leading type byte (`* $ + - : _ # , ( % ~ > ! =`), which is an
    //extremely WEAK signature: countless non-RESP byte streams begin with one of these bytes (`*` 0x2a, `+`
    //0x2b, `-` 0x2d, `:` 0x3a, `#` 0x23, `=` 0x3d, `,` 0x2c all appear in ordinary ASCII text and binary
    //data). Unlike HTTP/RTSP (multi-byte distinctive method sets), a 1-byte signature carries almost no
    //discriminating power. Joining the global heuristic chain would let Redis mis-claim essentially every
    //layer whose first byte happens to fall in that set, on ANY port — an unacceptable outcome. Confining
    //Redis to its tcp:6379 bucket makes that impossible off-port; alt-port Redis is rare and falls losslessly
    //to raw. (Even in-bucket, match() additionally sanity-checks the byte after `*`/`$`/`:` to further reduce
    //false claims — see match().)
    public readonly matchKeys: string[] = ['tcpport:6379']

    public match(): boolean {
        //RESP rides on TCP. Recognize it by the leading type byte only within the tcp:6379 bucket. To reduce
        //even in-bucket false claims from binary traffic that happens to start with a type byte, the numeric
        //framings `*` (array), `$` (bulk string) and `:` (integer) additionally require the next byte to be a
        //plausible count/length — a digit or `-` (RESP encodes null/negative counts as `$-1`, `*-1`). The
        //text framings (`+ - _ # , ( % ~ > ! =`) carry free-form content, so only the type byte is checked.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() < 1) return false
        const lead: Buffer = this.readBytes(0, 2, true)
        const type: string = String.fromCharCode(lead[0])
        if (!RESP_TYPE_BYTES.includes(type)) return false
        if (type === '*' || type === '$' || type === ':') {
            //Need the following byte to decide plausibility; a 1-byte segment is too short to trust.
            if (lead.length < 2) return false
            const next: number = lead[1]
            const isDigit: boolean = next >= 0x30 && next <= 0x39
            const isMinus: boolean = next === 0x2d
            if (!isDigit && !isMinus) return false
        }
        return true
    }

    //A leaf header — the Redis session / pipelined command stream it belongs to is a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
