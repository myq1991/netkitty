import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** SMTP command verbs (RFC 5321 + common extensions) used only to recognize a command line. */
const SMTP_COMMANDS: string[] = ['EHLO', 'HELO', 'MAIL', 'RCPT', 'DATA', 'RSET', 'VRFY', 'EXPN', 'HELP', 'NOOP', 'QUIT', 'AUTH', 'STARTTLS', 'BDAT']

/**
 * SMTP — the Simple Mail Transfer Protocol (RFC 5321), carried as US-ASCII text over TCP well-known
 * port 25 (and 587 for message submission). The control channel is line-based: a client sends commands
 * (`EHLO host\r\n`, `MAIL FROM:<a@b>\r\n`, `RCPT TO:<c@d>\r\n`, `DATA\r\n`, `QUIT\r\n`) and a server
 * sends replies (`220 mail.example.com ESMTP\r\n`, `250 OK\r\n`); a multi-line reply repeats the code
 * with a '-' after the first line (`250-STARTTLS\r\n250 OK\r\n`). The DATA message body follows the same
 * line channel but its arbitrary content is out of scope — only the control channel is claimed here.
 *
 * Like FTP, Syslog, SIP and HTTP, the message is text whose full internal structure (arbitrary
 * arguments, significant whitespace, multi-line reply continuations) is richer than a form needs. So the
 * ENTIRE raw message is kept verbatim as the authoritative `message` field (hex) and re-emitted
 * untouched; only the first line is parsed on decode into display-only metadata (command/argument for a
 * command, replyCode/replyText for a reply). Encode never reconstructs the message from the parsed
 * fields — it writes `message` back byte-for-byte — so any conformant (or even malformed) SMTP line
 * round-trips exactly.
 *
 * Note: a single TCP segment may carry more than one control line (pipelined commands) or only part of
 * a multi-line reply; reassembly across segments is out of scope. This single-segment codec keeps
 * whatever bytes are present verbatim, which is byte-perfect for the single-packet case.
 */
export class SMTP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SMTP.#schemaCache ??= SMTP.#buildSchema())
    }

    /**
     * Bytes of this header: SMTP rides on TCP, which has no per-message length, so take the rest of the
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
        const line: string = SMTP.#firstLine(text)
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
        //Command: VERB SP argument (the argument may itself contain spaces, e.g. an address path).
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
            summary: 'SMTP ${command}${replyCode}',
            properties: {
                //The whole raw message is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any SMTP control text). The first line is parsed
                //into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SMTP): void {
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
                    encode: function (this: SMTP): void {
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

    public readonly id: string = 'smtp'

    public readonly name: string = 'Simple Mail Transfer Protocol'

    public readonly nickname: string = 'SMTP'

    //SMTP is recognized ONLY on its well-known port buckets 25 (relay) and 587 (submission) —
    //deliberately NOT via heuristicFallback. Unlike HTTP/RTSP (whose method sets are distinctive),
    //SMTP's line signature is a 3-digit reply code or a generic verb (HELO/QUIT/NOOP/HELP/AUTH/DATA/…)
    //that is SHARED with other US-ASCII line protocols this codec does not model — FTP (QUIT/NOOP/AUTH/
    //HELP), POP3 (QUIT/NOOP), IRC (QUIT), and any NNN-code greeting (FTP/NNTP). Joining the global
    //heuristic chain would mislabel all of those as SMTP on their own ports. Confining SMTP to the
    //tcp:25/tcp:587 buckets keeps that collision impossible (FTP/POP3/IRC live on 21/110/6667, which
    //never reach these buckets); alt-port SMTP is rare and falls losslessly to raw.
    public readonly matchKeys: string[] = ['tcpport:25', 'tcpport:587']

    public match(): boolean {
        //SMTP rides on TCP as US-ASCII text. Recognize it by the line signature: a 3-digit reply code
        //followed by space or '-', or a known command verb as the leading token (up to the first space
        //or CR) — so non-SMTP traffic on port 25/587 falls through to raw rather than claiming an
        //un-decodable text layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() < 3) return false
        const lead: string = this.readBytes(0, 16, true).toString('latin1')
        if (/^\d{3}[ -]/.test(lead)) return true
        const line: string = SMTP.#firstLine(lead)
        const token: string = (line.split(/[ \r]/)[0] || '').toUpperCase()
        return SMTP_COMMANDS.includes(token)
    }

    //A leaf header — the DATA message body and the mail session it belongs to are a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
