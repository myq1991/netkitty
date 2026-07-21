import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** SSDP request methods (UPnP Device Architecture) used only to recognize a request start-line. */
const SSDP_METHODS: string[] = ['NOTIFY', 'M-SEARCH']

/**
 * SSDP — the Simple Service Discovery Protocol (UPnP Device Architecture), the discovery layer of UPnP
 * carried over UDP port 1900 (advertisements/searches to the multicast group 239.255.255.250, unicast
 * search responses). An SSDP message is HTTP/1.1-shaped US-ASCII text but is NOT HTTP: a start-line,
 * then header lines, and a terminating CRLF. Requests use `NOTIFY * HTTP/1.1` (advertise) or
 * `M-SEARCH * HTTP/1.1` (search); responses use a `HTTP/1.1 200 OK` Status-Line.
 *
 * Like SIP and HTTP, the message body is text whose full internal structure (HOST/NT/NTS/USN/ST/MAN/…
 * header fields, significant whitespace/header ordering/casing) is far richer than a form needs. So the
 * ENTIRE raw message is kept verbatim as the authoritative `message` field (hex) and re-emitted
 * untouched; only the start-line is parsed on decode into display-only metadata (method/uri/version or
 * status-code/reason). Encode never reconstructs the message from the parsed fields — it writes
 * `message` back byte-for-byte — so any conformant (or even malformed) SSDP message round-trips exactly.
 */
export class SSDP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SSDP.#schemaCache ??= SSDP.#buildSchema())
    }

    /**
     * Bytes of this header: SSDP rides on UDP, so it is bounded by the datagram length (so a retained
     * FCS/padding is not absorbed). Falls back to the rest of the captured buffer if the UDP length is
     * absent/implausible.
     */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
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
        const line: string = SSDP.#firstLine(text)
        if (line.startsWith('HTTP/')) {
            //Status-Line: HTTP-Version SP Status-Code SP Reason-Phrase
            const match: RegExpMatchArray | null = line.match(/^(\S+)\s+(\d{3})\s*(.*)$/)
            this.instance.isRequest.setValue(false)
            this.instance.method.setValue('')
            this.instance.requestUri.setValue('')
            this.instance.version.setValue(match ? match[1] : (line.split(' ')[0] || ''))
            this.instance.statusCode.setValue(match ? Number(match[2]) : 0)
            this.instance.reasonPhrase.setValue(match ? match[3] : '')
            //Info-column text for a response: "200 OK". Kept separate from the numeric statusCode so the
            //summary never renders a stray "0" for requests (whose statusCode is 0).
            this.instance.info.setValue((match ? match[2] : '') + (match && match[3] ? ' ' + match[3] : ''))
            return
        }
        //Request-Line: METHOD SP Request-URI SP HTTP-Version (Request-URI is "*" for SSDP)
        const parts: string[] = line.split(' ')
        this.instance.isRequest.setValue(true)
        this.instance.method.setValue(parts[0] ? parts[0] : '')
        this.instance.requestUri.setValue(parts.length > 1 ? parts[1] : '')
        //The HTTP-Version is the last whitespace-delimited token; the Request-URI itself has no spaces.
        this.instance.version.setValue(parts.length > 2 ? parts[parts.length - 1] : '')
        this.instance.statusCode.setValue(0)
        this.instance.reasonPhrase.setValue('')
        //Info-column text for a request: "M-SEARCH *".
        this.instance.info.setValue((parts[0] ? parts[0] : '') + (parts.length > 1 && parts[1] ? ' ' + parts[1] : ''))
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SSDP ${info}',
            properties: {
                //The whole raw message is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any SSDP message). The start-line is parsed into
                //the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SSDP): void {
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
                    encode: function (this: SSDP): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the start-line on decode (no encode — populated by the
                //message field above, never read back). isRequest distinguishes a Request-Line from a
                //Status-Line; method/requestUri are for requests, statusCode/reasonPhrase for responses.
                isRequest: {type: 'boolean', label: 'Is Request'},
                //Display-only Info-column text ("M-SEARCH *" / "200 OK"), set on decode; no encode, so it
                //never affects the re-emitted bytes.
                info: {type: 'string', label: 'Info'},
                method: {type: 'string', label: 'Method'},
                requestUri: {type: 'string', label: 'Request URI'},
                version: {type: 'string', label: 'Version'},
                statusCode: {type: 'integer', label: 'Status Code', minimum: 0, maximum: 999},
                reasonPhrase: {type: 'string', label: 'Reason Phrase'}
            }
        }
    }

    public readonly id: string = 'ssdp'

    public readonly name: string = 'Simple Service Discovery Protocol'

    public readonly nickname: string = 'SSDP'

    //SSDP is strictly UDP port 1900 — the port bucket alone dispatches. No heuristicFallback: the
    //start-line signature (NOTIFY/M-SEARCH/HTTP-1.1) overlaps HTTP, so recognition stays confined to the
    //1900 bucket to avoid claiming HTTP traffic on arbitrary ports.
    public readonly matchKeys: string[] = ['udpport:1900']

    public match(): boolean {
        //SSDP rides on UDP port 1900 as HTTP/1.1-shaped US-ASCII text. Recognize it by the start-line
        //signature: a known request method followed by a space (the trailing space rejects e.g.
        //"NOTIFYX"), or the "HTTP/1." response version — so non-SSDP traffic on port 1900 falls through
        //to raw rather than claiming an un-decodable text layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'udp') return false
        if (this.#payloadLength() <= 0) return false
        const lead: string = this.readBytes(0, 16, true).toString('latin1')
        if (lead.startsWith('HTTP/1.')) return true
        for (const method of SSDP_METHODS) {
            if (lead.startsWith(method + ' ')) return true
        }
        return false
    }

    //A leaf header — the referenced device description (LOCATION URL) and the discovery exchange are a
    //higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
