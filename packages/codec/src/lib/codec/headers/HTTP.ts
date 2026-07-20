import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** HTTP request methods (RFC 7231 + PATCH) used only to recognize a request start-line. */
const HTTP_METHODS: string[] = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']

/**
 * HTTP/1.x — the Hypertext Transfer Protocol (RFC 7230), carried as US-ASCII text over TCP (well-known
 * port 80, commonly 8080/8000). A message is a start-line, then header lines, a CRLF, and an optional
 * body. The start-line is either a Request-Line (`METHOD SP Request-URI SP HTTP-Version CRLF`) or a
 * Status-Line (`HTTP-Version SP Status-Code SP Reason-Phrase CRLF`).
 *
 * Like Syslog and SIP, the message body is text whose full internal structure (arbitrary header fields,
 * a body of any content-type, significant whitespace/header ordering/casing) is far richer than a form
 * needs. So the ENTIRE raw message is kept verbatim as the authoritative `message` field (hex) and
 * re-emitted untouched; only the start-line is parsed on decode into display-only metadata
 * (method/uri/version or status-code/reason). Encode never reconstructs the message from the parsed
 * fields — it writes `message` back byte-for-byte — so any conformant (or even malformed) HTTP message
 * round-trips exactly.
 *
 * Note: HTTP bodies can be chunked (`Transfer-Encoding: chunked`) or span multiple TCP segments;
 * reassembly across segments is out of scope. This single-segment codec keeps whatever bytes are
 * present in the current segment verbatim, which is byte-perfect for the single-packet case.
 */
export class HTTP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (HTTP.#schemaCache ??= HTTP.#buildSchema())
    }

    /**
     * Bytes of this header: HTTP rides on TCP, which has no per-message length, so take the rest of the
     * segment. Body reassembly across segments is out of scope (see class doc).
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
     * Parse the start-line into the display-only metadata fields. A Status-Line begins with the
     * HTTP-Version ("HTTP/1.1"); anything else is treated as a Request-Line. Populated on decode only —
     * these fields have no encode, so they never affect the re-emitted bytes and never mutate `message`.
     * Never throws: a non-numeric status yields 0, missing tokens yield empty strings.
     */
    #parseStartLine(text: string): void {
        const line: string = HTTP.#firstLine(text)
        if (line.startsWith('HTTP/')) {
            //Status-Line: HTTP-Version SP Status-Code SP Reason-Phrase
            const match: RegExpMatchArray | null = line.match(/^(\S+)\s+(\d{3})\s*(.*)$/)
            this.instance.isRequest.setValue(false)
            this.instance.method.setValue('')
            this.instance.requestUri.setValue('')
            this.instance.version.setValue(match ? match[1] : (line.split(' ')[0] || ''))
            this.instance.statusCode.setValue(match ? Number(match[2]) : 0)
            this.instance.reasonPhrase.setValue(match ? match[3] : '')
            return
        }
        //Request-Line: METHOD SP Request-URI SP HTTP-Version
        const parts: string[] = line.split(' ')
        this.instance.isRequest.setValue(true)
        this.instance.method.setValue(parts[0] ? parts[0] : '')
        this.instance.requestUri.setValue(parts.length > 1 ? parts[1] : '')
        //The HTTP-Version is the last whitespace-delimited token; the Request-URI itself has no spaces.
        this.instance.version.setValue(parts.length > 2 ? parts[parts.length - 1] : '')
        this.instance.statusCode.setValue(0)
        this.instance.reasonPhrase.setValue('')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'HTTP ${method}${statusCode}',
            properties: {
                //The whole raw message is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any HTTP message). The start-line is parsed into
                //the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: HTTP): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseStartLine('')
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseStartLine(raw.toString('latin1'))
                    },
                    encode: function (this: HTTP): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the start-line on decode (no encode — populated by the
                //message field above, never read back). isRequest distinguishes a Request-Line from a
                //Status-Line; method/requestUri are for requests, statusCode/reasonPhrase for responses.
                isRequest: {type: 'boolean', label: 'Is Request'},
                method: {type: 'string', label: 'Method'},
                requestUri: {type: 'string', label: 'Request URI'},
                version: {type: 'string', label: 'Version'},
                statusCode: {type: 'integer', label: 'Status Code', minimum: 0, maximum: 999},
                reasonPhrase: {type: 'string', label: 'Reason Phrase'}
            }
        }
    }

    public readonly id: string = 'http'

    public readonly name: string = 'Hypertext Transfer Protocol'

    public readonly nickname: string = 'HTTP'

    //The well-known ports give O(1) bucket dispatch, but HTTP runs on arbitrary ports (3000, 8888, proxy
    //ports, …). heuristicFallback lets a non-listed port still be recognized by the start-line signature
    //in match() below — the ports are a fast path, not a whitelist. (STUN uses the same pattern for its
    //Magic Cookie.) The signature is specific enough (a known method + space, or "HTTP/1.") that this
    //does not claim arbitrary TCP traffic.
    public readonly matchKeys: string[] = ['tcpport:80', 'tcpport:8080', 'tcpport:8000']

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        //HTTP rides on TCP as US-ASCII text. Recognize it by the start-line signature: a known request
        //method followed by a space (the trailing space rejects e.g. "GETX"), or the "HTTP/1." response
        //version — so non-HTTP traffic on these ports falls through to raw rather than claiming an
        //un-decodable text layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() < 4) return false
        const lead: string = this.readBytes(0, 16, true).toString('latin1')
        if (lead.startsWith('HTTP/1.')) return true
        for (const method of HTTP_METHODS) {
            if (lead.startsWith(method + ' ')) return true
        }
        return false
    }

    //A leaf header — the HTTP body and the exchange it belongs to are a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
