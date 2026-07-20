import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** RTSP request methods (RFC 2326 / RFC 7826) used only to recognize a request start-line. */
const RTSP_METHODS: string[] = ['DESCRIBE', 'ANNOUNCE', 'GET_PARAMETER', 'OPTIONS', 'PAUSE', 'PLAY', 'RECORD', 'REDIRECT', 'SETUP', 'SET_PARAMETER', 'TEARDOWN']

/**
 * RTSP — the Real Time Streaming Protocol (RFC 2326, obsoleted by RFC 7826), the control channel for
 * streaming media ("network remote control" for A/V servers) carried as US-ASCII text over TCP port
 * 554. RTSP borrows HTTP's syntax almost verbatim: a message is a start-line, then header lines, a
 * CRLF, and an optional body (e.g. an SDP description for a DESCRIBE response). The start-line is either
 * a Request-Line (`METHOD SP Request-URI SP RTSP-Version CRLF`) or a Status-Line (`RTSP-Version SP
 * Status-Code SP Reason-Phrase CRLF`). The only visible difference from HTTP is the version token
 * (`RTSP/1.0` instead of `HTTP/1.1`) and RTSP's own method set (DESCRIBE, SETUP, PLAY, …).
 *
 * Like HTTP and SIP, the message body is text whose full internal structure (arbitrary header fields, a
 * body of any content-type, significant whitespace/header ordering/casing) is far richer than a form
 * needs. So the ENTIRE raw message is kept verbatim as the authoritative `message` field (hex) and
 * re-emitted untouched; only the start-line (plus the RTSP-specific CSeq sequence number) is parsed on
 * decode into display-only metadata (method/uri/version or status-code/reason, and cseq). Encode never
 * reconstructs the message from the parsed fields — it writes `message` back byte-for-byte — so any
 * conformant (or even malformed) RTSP message round-trips exactly.
 *
 * Note: RTSP bodies (SDP, etc.) can span multiple TCP segments and RTSP can also interleave binary RTP
 * over the same TCP connection ($-framed); reassembly/interleaving across segments is out of scope.
 * This single-segment codec keeps whatever bytes are present in the current segment verbatim, which is
 * byte-perfect for the single-packet case.
 */
export class RTSP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (RTSP.#schemaCache ??= RTSP.#buildSchema())
    }

    /**
     * Bytes of this header: RTSP rides on TCP, which has no per-message length, so take the rest of the
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
     * The RTSP CSeq (sequence number): every RTSP request/response carries exactly one `CSeq:` header
     * pairing a response to its request. Scan the header lines for it (case-insensitive) and return the
     * first integer found, or 0 when absent/non-numeric. Display-only, like SIP's CSeq.
     */
    static #parseCSeq(text: string): number {
        for (const line of text.split('\r\n')) {
            const match: RegExpMatchArray | null = line.match(/^CSeq\s*:\s*(\d+)/i)
            if (match) return Number(match[1])
        }
        return 0
    }

    /**
     * Parse the start-line into the display-only metadata fields. A Status-Line begins with the
     * RTSP-Version ("RTSP/1.0"); anything else is treated as a Request-Line. Populated on decode only —
     * these fields have no encode, so they never affect the re-emitted bytes and never mutate `message`.
     * Never throws: a non-numeric status yields 0, missing tokens yield empty strings.
     */
    #parseStartLine(text: string): void {
        this.instance.cseq.setValue(RTSP.#parseCSeq(text))
        const line: string = RTSP.#firstLine(text)
        if (line.startsWith('RTSP/')) {
            //Status-Line: RTSP-Version SP Status-Code SP Reason-Phrase
            const match: RegExpMatchArray | null = line.match(/^(\S+)\s+(\d{3})\s*(.*)$/)
            this.instance.isRequest.setValue(false)
            this.instance.method.setValue('')
            this.instance.requestUri.setValue('')
            this.instance.version.setValue(match ? match[1] : (line.split(' ')[0] || ''))
            this.instance.statusCode.setValue(match ? Number(match[2]) : 0)
            this.instance.reasonPhrase.setValue(match ? match[3] : '')
            return
        }
        //Request-Line: METHOD SP Request-URI SP RTSP-Version
        const parts: string[] = line.split(' ')
        this.instance.isRequest.setValue(true)
        this.instance.method.setValue(parts[0] ? parts[0] : '')
        this.instance.requestUri.setValue(parts.length > 1 ? parts[1] : '')
        //The RTSP-Version is the last whitespace-delimited token; the Request-URI itself has no spaces.
        this.instance.version.setValue(parts.length > 2 ? parts[parts.length - 1] : '')
        this.instance.statusCode.setValue(0)
        this.instance.reasonPhrase.setValue('')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'RTSP ${method}${statusCode}',
            properties: {
                //The whole raw message is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any RTSP message). The start-line + CSeq are
                //parsed into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: RTSP): void {
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
                    encode: function (this: RTSP): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the start-line on decode (no encode — populated by the
                //message field above, never read back). isRequest distinguishes a Request-Line from a
                //Status-Line; method/requestUri are for requests, statusCode/reasonPhrase for responses;
                //cseq is RTSP's request/response sequence number (one per message).
                isRequest: {type: 'boolean', label: 'Is Request'},
                method: {type: 'string', label: 'Method'},
                requestUri: {type: 'string', label: 'Request URI'},
                version: {type: 'string', label: 'Version'},
                statusCode: {type: 'integer', label: 'Status Code', minimum: 0, maximum: 999},
                reasonPhrase: {type: 'string', label: 'Reason Phrase'},
                cseq: {type: 'integer', label: 'CSeq', minimum: 0}
            }
        }
    }

    public readonly id: string = 'rtsp'

    public readonly name: string = 'Real Time Streaming Protocol'

    public readonly nickname: string = 'RTSP'

    //The well-known port gives O(1) bucket dispatch, but RTSP (like HTTP) can run on arbitrary ports
    //(8554 is common for test servers). heuristicFallback lets a non-listed port still be recognized by
    //the start-line signature in match() below — the port is a fast path, not a whitelist. The signature
    //is specific enough (a known method + space, or "RTSP/") that this does not claim arbitrary TCP
    //traffic. See the HTTP header for the same rationale.
    public readonly matchKeys: string[] = ['tcpport:554']

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        //RTSP rides on TCP as US-ASCII text. Recognize it by the start-line signature: a known request
        //method followed by a space (the trailing space rejects e.g. "PLAYX"), or the "RTSP/" response
        //version — so non-RTSP traffic on this port falls through to raw rather than claiming an
        //un-decodable text layer.
        //
        //RTSP and HTTP both set heuristicFallback and both are text start-line protocols, so their
        //signatures must stay disjoint: RTSP checks "RTSP/" and the RTSP method set, HTTP checks "HTTP/1."
        //and the HTTP method set. DESCRIBE/SETUP/PLAY/… are not HTTP methods and "RTSP/" is not "HTTP/1.",
        //so neither claims the other's traffic. The one overlap is OPTIONS, which is a method in BOTH
        //sets: an "OPTIONS <uri> ..." line could be claimed by either at match() time. This is resolved by
        //port bucket on the well-known port (554 → RTSP, 80 → HTTP wins its own bucket) and, on an
        //arbitrary port reached via the heuristic chain, by registration order (first-registered wins).
        //The ambiguity is cosmetic only: both headers keep the message verbatim byte-perfect regardless of
        //which claims the OPTIONS line, so the round-trip bytes are identical either way; only the
        //displayed protocol nickname differs.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() < 4) return false
        const lead: string = this.readBytes(0, 16, true).toString('latin1')
        if (lead.startsWith('RTSP/')) return true
        for (const method of RTSP_METHODS) {
            if (lead.startsWith(method + ' ')) return true
        }
        return false
    }

    //A leaf header — the RTSP body (SDP, etc.) and the media session it controls are a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
