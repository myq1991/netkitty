import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** SIP request methods (RFC 3261 + common extensions) used only to recognize a request start-line. */
const SIP_METHODS: string[] = ['INVITE', 'ACK', 'BYE', 'CANCEL', 'OPTIONS', 'REGISTER', 'PRACK', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH', 'INFO', 'REFER', 'MESSAGE', 'UPDATE']

/**
 * SIP — the Session Initiation Protocol (RFC 3261), the signalling protocol for VoIP/IMS carried over
 * UDP or TCP port 5060. A SIP message is US-ASCII text: a start-line, then header lines, a CRLF, and an
 * optional body. The start-line is either a Request-Line (`METHOD SP Request-URI SP SIP-Version CRLF`)
 * or a Status-Line (`SIP-Version SP Status-Code SP Reason-Phrase CRLF`).
 *
 * Like Syslog, the message body is text whose full internal structure (dozens of header fields, an
 * arbitrary body of any content-type) is far richer than a form needs — and whitespace/header ordering
 * is significant to some peers. So the ENTIRE raw message is kept verbatim as the authoritative
 * `message` field (hex) and re-emitted untouched; only the start-line is parsed on decode into
 * display-only metadata (method/uri/version or status-code/reason). Encode never reconstructs the
 * message from the parsed fields — it writes `message` back byte-for-byte — so any conformant (or even
 * malformed) SIP message round-trips exactly.
 */
export class SIP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SIP.#schemaCache ??= SIP.#buildSchema())
    }

    /**
     * Bytes of this header: for UDP, bounded by the datagram length (so a retained FCS/padding is not
     * absorbed); for TCP there is no per-message length, so take the rest of the segment.
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
     * SIP-Version ("SIP/2.0"); anything else is treated as a Request-Line. Populated on decode only —
     * these fields have no encode, so they never affect the re-emitted bytes.
     */
    #parseStartLine(text: string): void {
        const line: string = SIP.#firstLine(text)
        if (line.startsWith('SIP/')) {
            //Status-Line: SIP-Version SP Status-Code SP Reason-Phrase
            const match: RegExpMatchArray | null = line.match(/^(\S+)\s+(\d{3})\s*(.*)$/)
            this.instance.isRequest.setValue(false)
            this.instance.method.setValue('')
            this.instance.requestUri.setValue('')
            this.instance.version.setValue(match ? match[1] : (line.split(' ')[0] || ''))
            this.instance.statusCode.setValue(match ? Number(match[2]) : 0)
            this.instance.reasonPhrase.setValue(match ? match[3] : '')
            return
        }
        //Request-Line: METHOD SP Request-URI SP SIP-Version
        const parts: string[] = line.split(' ')
        this.instance.isRequest.setValue(true)
        this.instance.method.setValue(parts[0] ? parts[0] : '')
        this.instance.requestUri.setValue(parts.length > 1 ? parts[1] : '')
        //The SIP-Version is the last whitespace-delimited token; the Request-URI itself has no spaces.
        this.instance.version.setValue(parts.length > 2 ? parts[parts.length - 1] : '')
        this.instance.statusCode.setValue(0)
        this.instance.reasonPhrase.setValue('')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SIP ${method}${statusCode}',
            properties: {
                //The whole raw message is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any SIP message). The start-line is parsed into
                //the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SIP): void {
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
                    encode: function (this: SIP): void {
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

    public readonly id: string = 'sip'

    public readonly name: string = 'Session Initiation Protocol'

    public readonly nickname: string = 'SIP'

    public readonly matchKeys: string[] = ['udpport:5060', 'tcpport:5060']

    public match(): boolean {
        //SIP rides on UDP/TCP port 5060 as US-ASCII text. Recognize it by the start-line signature: a
        //known request method followed by a space, or the "SIP/2.0" response version — so non-SIP
        //traffic on port 5060 falls through to raw rather than claiming an un-decodable text layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'udp' && this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() <= 0) return false
        const lead: string = this.readBytes(0, 16, true).toString('latin1')
        if (lead.startsWith('SIP/2.0')) return true
        for (const method of SIP_METHODS) {
            if (lead.startsWith(method + ' ')) return true
        }
        return false
    }

    //A leaf header — the SIP body (SDP, etc.) and the dialog it belongs to are a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
