import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** NNTP command verbs (RFC 3977 + common extensions) used only to recognize a command line. */
const NNTP_COMMANDS: string[] = ['ARTICLE', 'BODY', 'HEAD', 'STAT', 'GROUP', 'LISTGROUP', 'LAST', 'NEXT', 'POST', 'IHAVE', 'QUIT', 'CAPABILITIES', 'MODE', 'LIST', 'NEWGROUPS', 'NEWNEWS', 'OVER', 'XOVER', 'HDR', 'XHDR', 'HELP', 'DATE', 'AUTHINFO', 'STARTTLS']

/**
 * NNTP — the Network News Transfer Protocol (RFC 3977), carried as US-ASCII text over TCP well-known
 * port 119 (and 563 for NNTPS, the TLS-wrapped variant). The control channel is line-based and
 * structurally identical to SMTP: a client sends commands (`ARTICLE 123\r\n`, `GROUP misc.test\r\n`,
 * `POST\r\n`, `CAPABILITIES\r\n`, `QUIT\r\n`) and a server sends 3-digit-coded replies
 * (`200 news.example.com ready\r\n`, `211 1234 3000234 3002322 misc.test\r\n`, `340 send article\r\n`);
 * a multi-line reply repeats/marks the code with a '-' after the first line. The article/list data
 * blocks that follow certain replies use the same line channel but their arbitrary content is out of
 * scope — only the control channel is claimed here.
 *
 * Like SMTP, FTP, Syslog, SIP and HTTP, the message is text whose full internal structure (arbitrary
 * arguments, significant whitespace, multi-line reply continuations) is richer than a form needs. So the
 * ENTIRE raw message is kept verbatim as the authoritative `message` field (hex) and re-emitted
 * untouched; only the first line is parsed on decode into display-only metadata (command/argument for a
 * command, replyCode/replyText for a reply). Encode never reconstructs the message from the parsed
 * fields — it writes `message` back byte-for-byte — so any conformant (or even malformed) NNTP line
 * round-trips exactly.
 *
 * Note: a single TCP segment may carry more than one control line (pipelined commands) or only part of
 * a multi-line reply/article block; reassembly across segments is out of scope. This single-segment
 * codec keeps whatever bytes are present verbatim, which is byte-perfect for the single-packet case.
 */
export class NNTP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (NNTP.#schemaCache ??= NNTP.#buildSchema())
    }

    /**
     * Bytes of this header: NNTP rides on TCP, which has no per-message length, so take the rest of the
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
     * Parse the first line into the display-only metadata fields. A line matching `^\d{3}[ -]` is a
     * server reply (the code, whether it is multi-line, and the trailing text); anything else is a
     * client command (the uppercased verb and its argument). Populated on decode only — these fields
     * have no encode, so they never affect the re-emitted bytes and never mutate `message`. Never
     * throws: missing/garbage tokens yield empty strings or 0.
     */
    #parseFirstLine(text: string): void {
        const line: string = NNTP.#firstLine(text)
        const reply: RegExpMatchArray | null = line.match(/^(\d{3})([ -])(.*)$/)
        if (reply) {
            //Reply: 3-digit code, then ' ' (final) or '-' (a multi-line continuation follows).
            this.instance.isReply.setValue(true)
            this.instance.replyCode.setValue(Number(reply[1]))
            this.instance.isMultiline.setValue(reply[2] === '-')
            this.instance.replyText.setValue(reply[3])
            this.instance.command.setValue('')
            this.instance.argument.setValue('')
            return
        }
        //Command: VERB SP argument (the argument may itself contain spaces, e.g. a message-id or range).
        const idx: number = line.indexOf(' ')
        const verb: string = idx >= 0 ? line.slice(0, idx) : line
        this.instance.isReply.setValue(false)
        this.instance.replyCode.setValue(0)
        this.instance.isMultiline.setValue(false)
        this.instance.replyText.setValue('')
        this.instance.command.setValue(verb.toUpperCase())
        this.instance.argument.setValue(idx >= 0 ? line.slice(idx + 1) : '')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'NNTP ${command}${replyCode}',
            properties: {
                //The whole raw message is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any NNTP control text). The first line is parsed
                //into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: NNTP): void {
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
                    encode: function (this: NNTP): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the first line on decode (no encode — populated by the
                //message field above, never read back). isReply distinguishes a server reply from a
                //client command; replyCode/isMultiline/replyText describe a reply, command/argument a
                //command.
                isReply: {type: 'boolean', label: 'Is Reply'},
                replyCode: {type: 'integer', label: 'Reply Code', minimum: 0, maximum: 999},
                isMultiline: {type: 'boolean', label: 'Is Multiline'},
                replyText: {type: 'string', label: 'Reply Text'},
                command: {type: 'string', label: 'Command'},
                argument: {type: 'string', label: 'Argument'}
            }
        }
    }

    public readonly id: string = 'nntp'

    public readonly name: string = 'Network News Transfer Protocol'

    public readonly nickname: string = 'NNTP'

    //NNTP is recognized ONLY on its well-known port buckets 119 (news) and 563 (NNTPS/TLS) —
    //deliberately NOT via heuristicFallback. Unlike HTTP/RTSP (whose method sets are distinctive),
    //NNTP's line signature is a 3-digit reply code or a generic verb (QUIT/HELP/LIST/HEAD/BODY/STAT/…)
    //that is SHARED with other US-ASCII line protocols this codec models — SMTP (HELP/QUIT), FTP (QUIT/
    //HELP/LIST/STAT), POP3 (QUIT/STAT/LIST), IRC (QUIT), and any NNN-code greeting (FTP/SMTP). Joining
    //the global heuristic chain would mislabel all of those as NNTP on their own ports. Confining NNTP to
    //the tcp:119/tcp:563 buckets keeps that collision impossible (SMTP/FTP/POP3/IRC live on 25/21/110/
    //6667, which never reach these buckets); alt-port NNTP is rare and falls losslessly to raw. (NNTPS on
    //563 is normally TLS-wrapped, so the bucket rarely carries plain NNTP text, but is listed for
    //completeness/STARTTLS-downgrade traffic.)
    public readonly matchKeys: string[] = ['tcpport:119', 'tcpport:563']

    public match(): boolean {
        //NNTP rides on TCP as US-ASCII text. Recognize it by the line signature: a 3-digit reply code
        //followed by space or '-', or a known command verb as the leading token (up to the first space
        //or CR) — so non-NNTP traffic on port 119/563 falls through to raw rather than claiming an
        //un-decodable text layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() < 3) return false
        const lead: string = this.readBytes(0, 16, true).toString('latin1')
        if (/^\d{3}[ -]/.test(lead)) return true
        const line: string = NNTP.#firstLine(lead)
        const token: string = (line.split(/[ \r]/)[0] || '').toUpperCase()
        return NNTP_COMMANDS.includes(token)
    }

    //A leaf header — the article/list data blocks and the news session they belong to are a higher-layer
    //concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
