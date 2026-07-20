import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** IMAP command verbs (RFC 3501 + STARTTLS/IDLE) used only to recognize a `<tag> VERB` command line. */
const IMAP_COMMANDS: string[] = ['CAPABILITY', 'NOOP', 'LOGOUT', 'STARTTLS', 'AUTHENTICATE', 'LOGIN', 'SELECT', 'EXAMINE', 'CREATE', 'DELETE', 'RENAME', 'SUBSCRIBE', 'UNSUBSCRIBE', 'LIST', 'LSUB', 'STATUS', 'APPEND', 'CHECK', 'CLOSE', 'EXPUNGE', 'SEARCH', 'FETCH', 'STORE', 'COPY', 'UID', 'IDLE']

/** IMAP status conditions (RFC 3501 §7.1) that a tagged/untagged server response carries after its prefix. */
const IMAP_STATUSES: string[] = ['OK', 'NO', 'BAD', 'PREAUTH', 'BYE']

/**
 * IMAP — the Internet Message Access Protocol version 4rev1 (RFC 3501), carried as US-ASCII text over TCP
 * well-known port 143 (or 993 for the TLS-wrapped IMAPS bucket). The control channel is line-based and
 * TAG-prefixed: a client sends `<tag> COMMAND args\r\n` (`a001 LOGIN alice secret\r\n`, `A2 SELECT INBOX\r\n`)
 * and the server answers with either a tagged status completion (`a001 OK LOGIN completed\r\n`), an
 * untagged response (`* OK IMAP4rev1 ready\r\n`, `* 18 EXISTS\r\n`), or a command continuation request
 * (`+ Ready for literal data\r\n`).
 *
 * Like FTP, SMTP, POP3, Syslog, SIP and HTTP, the message is text whose full internal structure (arbitrary
 * arguments, significant whitespace, literals, multi-line untagged responses) is richer than a form needs.
 * So the ENTIRE raw message is kept verbatim as the authoritative `message` field (hex) and re-emitted
 * untouched; only the first line is parsed on decode into display-only metadata (kind/tag/command/status/
 * text). Encode never reconstructs the message from the parsed fields — it writes `message` back
 * byte-for-byte — so any conformant (or even malformed) IMAP line round-trips exactly.
 *
 * Note: a single TCP segment may carry more than one line or only part of a multi-line/literal response;
 * reassembly across segments is out of scope. This single-segment codec keeps whatever bytes are present
 * verbatim, which is byte-perfect for the single-packet case.
 */
export class IMAP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (IMAP.#schemaCache ??= IMAP.#buildSchema())
    }

    /**
     * Bytes of this header: IMAP rides on TCP, which has no per-message length, so take the rest of the
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
     * Parse the first line into the display-only metadata fields. The first token selects the shape:
     * `*` → an untagged server response; `+` → a continuation request; anything else is a TAG, and the
     * second token then decides between a tagged RESPONSE (when it is an OK/NO/BAD/PREAUTH/BYE status) and
     * a client COMMAND (when it is a verb). Populated on decode only — these fields have no encode, so they
     * never affect the re-emitted bytes and never mutate `message`. Never throws: missing/garbage tokens
     * yield empty strings.
     */
    #parseFirstLine(text: string): void {
        const line: string = IMAP.#firstLine(text)
        const sp1: number = line.indexOf(' ')
        const first: string = sp1 >= 0 ? line.slice(0, sp1) : line
        const rest: string = sp1 >= 0 ? line.slice(sp1 + 1) : ''
        if (first === '*') {
            //Untagged server response: `* <status?> <text>` (e.g. `* OK ...`, `* 18 EXISTS`).
            const sp2: number = rest.indexOf(' ')
            const second: string = (sp2 >= 0 ? rest.slice(0, sp2) : rest).toUpperCase()
            const isStatus: boolean = IMAP_STATUSES.includes(second)
            this.instance.kind.setValue('untagged')
            this.instance.tag.setValue('')
            this.instance.command.setValue('')
            this.instance.status.setValue(isStatus ? second : '')
            this.instance.text.setValue(isStatus ? (sp2 >= 0 ? rest.slice(sp2 + 1) : '') : rest)
            return
        }
        if (first === '+') {
            //Continuation request: `+ <text>` — the server asks the client to send more (e.g. a literal).
            this.instance.kind.setValue('continuation')
            this.instance.tag.setValue('')
            this.instance.command.setValue('')
            this.instance.status.setValue('')
            this.instance.text.setValue(rest)
            return
        }
        //Tagged line: the first token is the TAG. The second token is either a status (tagged response) or
        //a verb (client command).
        const sp2: number = rest.indexOf(' ')
        const second: string = (sp2 >= 0 ? rest.slice(0, sp2) : rest).toUpperCase()
        const remainder: string = sp2 >= 0 ? rest.slice(sp2 + 1) : ''
        this.instance.tag.setValue(first)
        if (IMAP_STATUSES.includes(second)) {
            this.instance.kind.setValue('tagged')
            this.instance.command.setValue('')
            this.instance.status.setValue(second)
            this.instance.text.setValue(remainder)
            return
        }
        this.instance.kind.setValue('command')
        this.instance.command.setValue(second)
        this.instance.status.setValue('')
        this.instance.text.setValue(remainder)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'IMAP ${command}${status}',
            properties: {
                //The whole raw message is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any IMAP control text). The first line is parsed
                //into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: IMAP): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseFirstLine('')
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseFirstLine(raw.toString('latin1'))
                    },
                    encode: function (this: IMAP): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the first line on decode (no encode — populated by the
                //message field above, never read back). kind distinguishes the four line shapes; tag is the
                //command/response tag (empty for untagged/continuation); command/status/text describe the
                //recognized tokens.
                kind: {type: 'string', label: 'Kind'},
                tag: {type: 'string', label: 'Tag'},
                command: {type: 'string', label: 'Command'},
                status: {type: 'string', label: 'Status'},
                text: {type: 'string', label: 'Text'}
            }
        }
    }

    public readonly id: string = 'imap'

    public readonly name: string = 'Internet Message Access Protocol'

    public readonly nickname: string = 'IMAP'

    //IMAP is recognized ONLY on its well-known port buckets 143 (cleartext) and 993 (TLS-wrapped IMAPS) —
    //deliberately NOT via heuristicFallback. Like SMTP/POP3, and unlike HTTP/RTSP (whose method sets are
    //distinctive), IMAP's line signature is a generic `<tag> VERB`/`<tag> OK` shape whose second token
    //(LOGIN/SELECT/LIST/STATUS/SEARCH/OK/NO/BAD/…) is SHARED with other US-ASCII line protocols this codec
    //models — FTP (LIST/STATUS as STAT-family, generic verbs) and the plain OK/NO/BAD status words appear
    //in many text protocols. Joining the global heuristic chain would let IMAP mislabel such a line on
    //another protocol's port as IMAP (and vice-versa). Confining IMAP to its tcp:143/tcp:993 buckets keeps
    //that collision impossible; alt-port IMAP is rare and falls losslessly to raw. (IMAPS on 993 is
    //normally TLS-wrapped, so the bucket rarely carries plain IMAP text, but is listed for completeness.)
    public readonly matchKeys: string[] = ['tcpport:143', 'tcpport:993']

    public match(): boolean {
        //IMAP rides on TCP as US-ASCII, TAG-prefixed text. Recognize it by the line signature: an `* `
        //(untagged) or `+ ` (continuation) server prefix, or a `<tag> <VERB-or-status>` shape whose second
        //token is a known IMAP verb or an OK/NO/BAD/PREAUTH/BYE status — so non-IMAP traffic on port
        //143/993 falls through to raw rather than claiming an un-decodable text layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() < 3) return false
        const lead: string = this.readBytes(0, 32, true).toString('latin1')
        if (/^\* /.test(lead)) return true
        if (/^\+ /.test(lead)) return true
        const line: string = IMAP.#firstLine(lead)
        const sp1: number = line.indexOf(' ')
        if (sp1 < 0) return false
        const second: string = (line.slice(sp1 + 1).split(/[ \r]/)[0] || '').toUpperCase()
        return IMAP_COMMANDS.includes(second) || IMAP_STATUSES.includes(second)
    }

    //A leaf header — the IMAP session it belongs to is a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
