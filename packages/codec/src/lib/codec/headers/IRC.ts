import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** IRC command words (RFC 1459 / RFC 2812 + CAP/SASL) used only to recognize a message line. */
const IRC_COMMANDS: string[] = ['PASS', 'NICK', 'USER', 'OPER', 'MODE', 'SERVICE', 'QUIT', 'SQUIT', 'JOIN', 'PART', 'TOPIC', 'NAMES', 'LIST', 'INVITE', 'KICK', 'PRIVMSG', 'NOTICE', 'MOTD', 'LUSERS', 'VERSION', 'STATS', 'LINKS', 'TIME', 'CONNECT', 'TRACE', 'ADMIN', 'INFO', 'SERVLIST', 'SQUERY', 'WHO', 'WHOIS', 'WHOWAS', 'KILL', 'PING', 'PONG', 'ERROR', 'AWAY', 'REHASH', 'DIE', 'RESTART', 'SUMMON', 'USERS', 'WALLOPS', 'USERHOST', 'ISON', 'CAP', 'AUTHENTICATE']

/**
 * IRC — the Internet Relay Chat protocol (RFC 1459 / RFC 2812), carried as US-ASCII text over TCP
 * well-known port 6667 (or 6697 for the TLS-wrapped IRC-over-TLS bucket). The channel is line-based: each
 * message is an optional `:prefix` (source), then a COMMAND (a verb word like PRIVMSG/JOIN/NICK, or a
 * 3-digit numeric reply code such as 001/433), then space-separated params with an optional ` :trailing`
 * argument, terminated by CRLF. A client sends `NICK alice\r\n`, `JOIN #chan\r\n`, `PRIVMSG #chan :hi\r\n`;
 * a server prefixes its messages with the source (`:server 001 alice :Welcome\r\n`,
 * `:nick!user@host PRIVMSG #chan :hi\r\n`).
 *
 * Like FTP, SMTP, POP3, Syslog, SIP and HTTP, the message is text whose full internal structure
 * (arbitrary params, significant whitespace, an optional trailing argument, multiple lines per segment)
 * is richer than a form needs. So the ENTIRE raw message is kept verbatim as the authoritative `message`
 * field (hex) and re-emitted untouched; only the FIRST line is parsed on decode into display-only
 * metadata (prefix/command/params/isNumeric). Encode never reconstructs the message from the parsed
 * fields — it writes `message` back byte-for-byte — so any conformant (or even malformed) IRC line
 * round-trips exactly.
 *
 * Note: a single TCP segment may carry more than one line (IRC peers pipeline freely) or only part of a
 * line; reassembly across segments is out of scope. This single-segment codec keeps whatever bytes are
 * present verbatim, which is byte-perfect for the single-packet case.
 */
export class IRC extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (IRC.#schemaCache ??= IRC.#buildSchema())
    }

    /**
     * Bytes of this header: IRC rides on TCP, which has no per-message length, so take the rest of the
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
     * Parse the first line into the display-only metadata fields. An IRC message is
     * `[':' prefix SP] COMMAND [params] [SP ':' trailing]`: if the line begins with `:` the token up to
     * the first space is the source prefix (e.g. 'server' or 'nick!user@host'), otherwise there is no
     * prefix. The COMMAND is the next token — kept as-is when it is a 3-digit numeric reply code,
     * uppercased when it is a verb word; params is the remainder of the line (including any `:trailing`).
     * Populated on decode only — these fields have no encode, so they never affect the re-emitted bytes
     * and never mutate `message`. This is a pragmatic display split; never throws: missing/garbage tokens
     * yield empty strings.
     */
    #parseFirstLine(text: string): void {
        const line: string = IRC.#firstLine(text)
        let rest: string = line
        let prefix: string = ''
        if (rest.startsWith(':')) {
            //A prefixed (server-originated) message: ':' source SP <rest>.
            const sp: number = rest.indexOf(' ')
            if (sp >= 0) {
                prefix = rest.slice(1, sp)
                rest = rest.slice(sp + 1).replace(/^ +/, '')
            } else {
                prefix = rest.slice(1)
                rest = ''
            }
        }
        //COMMAND is the leading token of what remains; params is everything after it.
        const idx: number = rest.indexOf(' ')
        const rawCommand: string = idx >= 0 ? rest.slice(0, idx) : rest
        const params: string = idx >= 0 ? rest.slice(idx + 1) : ''
        const isNumeric: boolean = /^\d{3}$/.test(rawCommand)
        this.instance.prefix.setValue(prefix)
        this.instance.command.setValue(isNumeric ? rawCommand : rawCommand.toUpperCase())
        this.instance.params.setValue(params)
        this.instance.isNumeric.setValue(isNumeric)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'IRC ${command}',
            properties: {
                //The whole raw message is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any IRC message text). The first line is parsed
                //into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: IRC): void {
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
                    encode: function (this: IRC): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the first line on decode (no encode — populated by the
                //message field above, never read back). prefix is the optional message source; command is
                //the verb word or numeric reply code; params is the remainder (including any :trailing);
                //isNumeric marks a 3-digit numeric reply.
                prefix: {type: 'string', label: 'Prefix'},
                command: {type: 'string', label: 'Command'},
                params: {type: 'string', label: 'Params'},
                isNumeric: {type: 'boolean', label: 'Is Numeric'}
            }
        }
    }

    public readonly id: string = 'irc'

    public readonly name: string = 'Internet Relay Chat'

    public readonly nickname: string = 'IRC'

    //IRC is recognized ONLY on its well-known port buckets 6667 (plaintext) and 6697 (IRC-over-TLS) —
    //deliberately NOT via heuristicFallback. Unlike HTTP/RTSP (whose method sets are distinctive), IRC's
    //line signature is a generic verb (USER/QUIT/LIST/…) or a 3-digit numeric that is SHARED with other
    //US-ASCII line protocols this codec also models — FTP (USER/QUIT/LIST + NNN codes), POP3/SMTP
    //(USER/QUIT). The FTP code review found exactly this collision: an IRC `USER`/`QUIT` line is
    //indistinguishable from an FTP one. Joining the global heuristic chain would let IRC mislabel an FTP
    //`USER`/`LIST` line (or an FTP NNN greeting) on tcp:21 as IRC (and vice-versa). Confining IRC to the
    //tcp:6667/tcp:6697 buckets keeps that collision impossible (FTP/POP3/SMTP live on 21/110/25, which
    //never reach these buckets); alt-port IRC is rare and falls losslessly to raw. (IRC-over-TLS on 6697
    //is normally TLS-wrapped, so the bucket rarely carries plain IRC text, but is listed for completeness.)
    public readonly matchKeys: string[] = ['tcpport:6667', 'tcpport:6697']

    public match(): boolean {
        //IRC rides on TCP as US-ASCII text. Recognize it by the line signature: either a prefixed
        //server message (`:` source SP COMMAND …) whose command token is a known verb/numeric, or a
        //leading token that is itself a known verb/numeric — so non-IRC traffic on port 6667/6697 falls
        //through to raw rather than claiming an un-decodable text layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() < 4) return false
        const lead: string = this.readBytes(0, 128, true).toString('latin1')
        const line: string = IRC.#firstLine(lead)
        if (line.startsWith(':')) {
            //A prefixed message: require ':' + a non-space source, then a space, then a command token.
            //This keeps the `:` branch from over-claiming (a bare `:` or `: …` is not IRC).
            const sp: number = line.indexOf(' ')
            if (sp <= 1) return false
            const rest: string = line.slice(sp + 1).replace(/^ +/, '')
            const token: string = (rest.split(/[ \r]/)[0] || '').toUpperCase()
            if (!token) return false
            return /^\d{3}$/.test(token) || IRC_COMMANDS.includes(token)
        }
        //An unprefixed (typically client) message: the leading token must be a known verb or numeric.
        const token: string = (line.split(/[ \r]/)[0] || '').toUpperCase()
        return /^\d{3}$/.test(token) || IRC_COMMANDS.includes(token)
    }

    //A leaf header — the IRC session/dialog it belongs to is a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
