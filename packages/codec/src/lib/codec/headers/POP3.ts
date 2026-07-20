import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** POP3 command verbs (RFC 1939 + STLS/CAPA extensions) used only to recognize a command line. */
const POP3_COMMANDS: string[] = ['USER', 'PASS', 'APOP', 'STAT', 'LIST', 'RETR', 'DELE', 'NOOP', 'RSET', 'QUIT', 'TOP', 'UIDL', 'CAPA', 'STLS']

/**
 * POP3 — the Post Office Protocol version 3 (RFC 1939), carried as US-ASCII text over TCP well-known
 * port 110 (or 995 for the TLS-wrapped POP3S bucket). The control channel is line-based: a client sends
 * commands (`USER alice\r\n`, `PASS x\r\n`, `RETR 1\r\n`, `QUIT\r\n`, …) and a server sends replies whose
 * syntax DIFFERS from FTP/SMTP — instead of a 3-digit code, a POP3 reply is a status indicator:
 * `+OK ...\r\n` (success) or `-ERR ...\r\n` (failure).
 *
 * Like FTP, Syslog, SIP and HTTP, the message is text whose full internal structure (arbitrary arguments,
 * significant whitespace, multi-line RETR/LIST responses) is richer than a form needs. So the ENTIRE raw
 * message is kept verbatim as the authoritative `message` field (hex) and re-emitted untouched; only the
 * first line is parsed on decode into display-only metadata (command/argument for a command,
 * status/replyText for a reply). Encode never reconstructs the message from the parsed fields — it writes
 * `message` back byte-for-byte — so any conformant (or even malformed) POP3 line round-trips exactly.
 *
 * Note: a single TCP segment may carry more than one line or only part of a multi-line response;
 * reassembly across segments is out of scope. This single-segment codec keeps whatever bytes are present
 * verbatim, which is byte-perfect for the single-packet case.
 */
export class POP3 extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (POP3.#schemaCache ??= POP3.#buildSchema())
    }

    /**
     * Bytes of this header: POP3 rides on TCP, which has no per-message length, so take the rest of the
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
     * Parse the first line into the display-only metadata fields. A line beginning with `+OK` or `-ERR`
     * is a server reply (the status indicator and the trailing text); anything else is a client command
     * (the uppercased verb and its argument). Populated on decode only — these fields have no encode, so
     * they never affect the re-emitted bytes and never mutate `message`. Never throws: missing/garbage
     * tokens yield empty strings.
     */
    #parseFirstLine(text: string): void {
        const line: string = POP3.#firstLine(text)
        const reply: RegExpMatchArray | null = line.match(/^(\+OK|-ERR)(?: (.*))?$/)
        if (reply) {
            //Reply: a status indicator (+OK success / -ERR failure), then optional trailing text.
            this.instance.isReply.setValue(true)
            this.instance.status.setValue(reply[1])
            this.instance.replyText.setValue(reply[2] ?? '')
            this.instance.command.setValue('')
            this.instance.argument.setValue('')
            return
        }
        //Command: VERB SP argument (the argument may itself contain spaces, e.g. `APOP name digest`).
        const idx: number = line.indexOf(' ')
        const verb: string = idx >= 0 ? line.slice(0, idx) : line
        this.instance.isReply.setValue(false)
        this.instance.status.setValue('')
        this.instance.replyText.setValue('')
        this.instance.command.setValue(verb.toUpperCase())
        this.instance.argument.setValue(idx >= 0 ? line.slice(idx + 1) : '')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'POP3 ${command}${status}',
            properties: {
                //The whole raw message is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any POP3 control text). The first line is parsed
                //into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: POP3): void {
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
                    encode: function (this: POP3): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the first line on decode (no encode — populated by the
                //message field above, never read back). isReply distinguishes a server reply from a
                //client command; status/replyText describe a reply, command/argument a command.
                isReply: {type: 'boolean', label: 'Is Reply'},
                status: {type: 'string', label: 'Status'},
                replyText: {type: 'string', label: 'Reply Text'},
                command: {type: 'string', label: 'Command'},
                argument: {type: 'string', label: 'Argument'}
            }
        }
    }

    public readonly id: string = 'pop3'

    public readonly name: string = 'Post Office Protocol v3'

    public readonly nickname: string = 'POP3'

    //POP3 is recognized ONLY on its well-known port buckets (110, and 995 for TLS-wrapped POP3S) —
    //deliberately NOT via heuristicFallback. Unlike HTTP/RTSP (whose method sets are distinctive), POP3's
    //line signature is a `+OK`/`-ERR` status or a generic verb (USER/PASS/STAT/LIST/RETR/QUIT/…) that is
    //SHARED with other US-ASCII line protocols this codec also models — FTP (USER/PASS/STAT/LIST/RETR/
    //QUIT). Joining the global heuristic chain would let POP3 mislabel an FTP `USER`/`STAT`/`RETR` line
    //on tcp:21 as POP3 (and vice-versa). Confining POP3 to its tcp:110/tcp:995 buckets keeps that
    //collision impossible (FTP lives on 21, which never reaches these buckets); alt-port POP3 is rare and
    //falls losslessly to raw. (POP3S on 995 is normally TLS-wrapped, so the bucket rarely carries plain
    //POP3 text, but is listed for completeness/STLS-downgrade traffic.)
    public readonly matchKeys: string[] = ['tcpport:110', 'tcpport:995']

    public match(): boolean {
        //POP3 rides on TCP as US-ASCII text. Recognize it by the line signature: a `+OK`/`-ERR` status
        //indicator, or a known command verb as the leading token (up to the first space or CR) — so
        //non-POP3 traffic on port 110/995 falls through to raw rather than claiming an un-decodable text
        //layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() < 3) return false
        const lead: string = this.readBytes(0, 16, true).toString('latin1')
        if (/^(\+OK|-ERR)/.test(lead)) return true
        const line: string = POP3.#firstLine(lead)
        const token: string = (line.split(/[ \r]/)[0] || '').toUpperCase()
        return POP3_COMMANDS.includes(token)
    }

    //A leaf header — the POP3 session it belongs to is a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
