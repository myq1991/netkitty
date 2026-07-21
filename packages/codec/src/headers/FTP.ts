import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** FTP command verbs (RFC 959 + common extensions) used only to recognize a command line. */
const FTP_COMMANDS: string[] = ['USER', 'PASS', 'ACCT', 'CWD', 'CDUP', 'QUIT', 'PORT', 'PASV', 'TYPE', 'RETR', 'STOR', 'LIST', 'NLST', 'DELE', 'MKD', 'RMD', 'PWD', 'SYST', 'FEAT', 'EPSV', 'EPRT', 'SIZE', 'MDTM', 'RNFR', 'RNTO', 'NOOP', 'OPTS', 'AUTH', 'HELP', 'STAT', 'ABOR', 'REST', 'APPE']

/**
 * FTP — the File Transfer Protocol control channel (RFC 959), carried as US-ASCII text over TCP
 * well-known port 21. The control channel is line-based: a client sends commands
 * (`USER anonymous\r\n`, `PASS x\r\n`, `RETR file\r\n`, …) and a server sends replies
 * (`220 Service ready\r\n`, `331 …\r\n`); a multi-line reply repeats the code with a '-' after the
 * first line (`220-…\r\n…\r\n220 …\r\n`). The bulk data transfer runs on a separate dynamic-port
 * connection which is out of scope — only the control channel on port 21 is claimed here (like TFTP,
 * whose data channel is likewise not claimed).
 *
 * Like Syslog, SIP and HTTP, the message is text whose full internal structure (arbitrary arguments,
 * significant whitespace, multi-line reply continuations) is richer than a form needs. So the ENTIRE
 * raw message is kept verbatim as the authoritative `message` field (hex) and re-emitted untouched;
 * only the first line is parsed on decode into display-only metadata (command/argument for a command,
 * replyCode/replyText for a reply). Encode never reconstructs the message from the parsed fields — it
 * writes `message` back byte-for-byte — so any conformant (or even malformed) FTP line round-trips
 * exactly.
 *
 * Note: a single TCP segment may carry more than one control line (pipelined commands) or only part of
 * a multi-line reply; reassembly across segments is out of scope. This single-segment codec keeps
 * whatever bytes are present verbatim, which is byte-perfect for the single-packet case.
 */
export class FTP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (FTP.#schemaCache ??= FTP.#buildSchema())
    }

    /**
     * Bytes of this header: FTP rides on TCP, which has no per-message length, so take the rest of the
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
        const line: string = FTP.#firstLine(text)
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
        //Command: VERB SP argument (the argument may itself contain spaces, e.g. a path).
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
            summary: 'FTP ${command}${replyCode}',
            properties: {
                //The whole raw message is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any FTP control text). The first line is parsed
                //into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: FTP): void {
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
                    encode: function (this: FTP): void {
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

    public readonly id: string = 'ftp'

    public readonly name: string = 'File Transfer Protocol'

    public readonly nickname: string = 'FTP'

    //FTP is recognized ONLY on the well-known control port 21 — deliberately NOT via heuristicFallback.
    //Unlike HTTP/RTSP (whose method sets are distinctive), FTP's line signature is a 3-digit reply code
    //or a generic verb (USER/PASS/LIST/STAT/QUIT/RETR/…) that is SHARED with other US-ASCII line
    //protocols this codec does not model — POP3 (USER/PASS/STAT/LIST/RETR/QUIT), SMTP (AUTH/QUIT/NOOP),
    //IRC (USER/QUIT), and any NNN-code greeting (SMTP/NNTP). Joining the global heuristic chain would
    //mislabel all of those as FTP on their own ports. Confining FTP to the tcp:21 bucket keeps that
    //collision impossible (POP3/SMTP/IRC live on 110/25/6667, which never reach this bucket); alt-port
    //FTP control is rare and falls losslessly to raw.
    public readonly matchKeys: string[] = ['tcpport:21']

    public match(): boolean {
        //FTP rides on TCP as US-ASCII text. Recognize it by the line signature: a 3-digit reply code
        //followed by space or '-', or a known command verb as the leading token (up to the first space
        //or CR) — so non-FTP traffic on port 21 falls through to raw rather than claiming an
        //un-decodable text layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() < 3) return false
        const lead: string = this.readBytes(0, 16, true).toString('latin1')
        if (/^\d{3}[ -]/.test(lead)) return true
        const line: string = FTP.#firstLine(lead)
        const token: string = (line.split(/[ \r]/)[0] || '').toUpperCase()
        return FTP_COMMANDS.includes(token)
    }

    //A leaf header — the FTP data channel and the session it belongs to are a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
