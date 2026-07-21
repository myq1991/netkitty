import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** MGCP verbs (RFC 3435 §3.2 + common extensions) used only to recognize a command start-line. */
const MGCP_VERBS: string[] = ['CRCX', 'MDCX', 'DLCX', 'RQNT', 'NTFY', 'AUEP', 'AUCX', 'RSIP', 'EPCF']

/**
 * MGCP — the Media Gateway Control Protocol (RFC 3435), the master/slave signalling protocol by which a
 * Call Agent controls media gateways for VoIP. It is US-ASCII text carried over UDP (gateways listen on
 * 2427, call agents on 2727). A message is a command or response line, then parameter lines, a blank
 * line, and an optional SDP session description.
 *
 * The command line is `VERB SP transactionId SP endpoint SP "MGCP 1.0" CRLF` (VERB ∈ CRCX/MDCX/DLCX/…);
 * a response line is `responseCode SP transactionId SP commentText CRLF`.
 *
 * Like SIP and HTTP, the message body is text whose full internal structure (arbitrary parameter lines,
 * an embedded SDP session, significant whitespace/line ordering) is far richer than a form needs. So the
 * ENTIRE raw message is kept verbatim as the authoritative `message` field (hex) and re-emitted
 * untouched; only the first line is parsed on decode into display-only metadata
 * (verb/transactionId/endpoint/version or responseCode/comment). Encode never reconstructs the message
 * from the parsed fields — it writes `message` back byte-for-byte — so any conformant (or even
 * malformed) MGCP message round-trips exactly.
 */
export class MGCP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (MGCP.#schemaCache ??= MGCP.#buildSchema())
    }

    /**
     * Bytes of this header: for UDP, bounded by the datagram length (so a retained FCS/padding is not
     * absorbed); otherwise take the rest of the packet. Never negative.
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
     * Parse the first line into the display-only metadata fields. A response line begins with a 3-digit
     * numeric code; anything else is treated as a command line. Populated on decode only — these fields
     * have no encode, so they never affect the re-emitted bytes. Never throws: missing tokens yield
     * empty strings, a non-numeric code yields 0.
     */
    #parseFirstLine(text: string): void {
        const line: string = MGCP.#firstLine(text)
        const parts: string[] = line.split(' ')
        if (/^\d{3}$/.test(parts[0] || '')) {
            //Response line: responseCode SP transactionId SP commentText
            this.instance.isResponse.setValue(true)
            this.instance.verb.setValue('')
            this.instance.transactionId.setValue(parts.length > 1 ? parts[1] : '')
            this.instance.endpoint.setValue('')
            this.instance.version.setValue('')
            this.instance.responseCode.setValue(Number(parts[0]))
            this.instance.comment.setValue(parts.length > 2 ? parts.slice(2).join(' ') : '')
            return
        }
        //Command line: VERB SP transactionId SP endpoint SP "MGCP 1.0"
        this.instance.isResponse.setValue(false)
        this.instance.verb.setValue(parts[0] ? parts[0] : '')
        this.instance.transactionId.setValue(parts.length > 1 ? parts[1] : '')
        this.instance.endpoint.setValue(parts.length > 2 ? parts[2] : '')
        //The MGCP-Version is the trailing "MGCP 1.0" (last two tokens); keep whatever tokens follow the
        //endpoint so a non-standard version string is still displayed.
        this.instance.version.setValue(parts.length > 3 ? parts.slice(3).join(' ') : '')
        this.instance.responseCode.setValue(0)
        this.instance.comment.setValue('')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'MGCP ${verb}${responseCode}',
            properties: {
                //The whole raw message is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any MGCP message). The first line is parsed into
                //the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: MGCP): void {
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
                    encode: function (this: MGCP): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the first line on decode (no encode — populated by the
                //message field above, never read back). isResponse distinguishes a response line from a
                //command line; verb/endpoint/version are for commands, responseCode/comment for responses.
                isResponse: {type: 'boolean', label: 'Is Response'},
                verb: {type: 'string', label: 'Verb'},
                transactionId: {type: 'string', label: 'Transaction ID'},
                endpoint: {type: 'string', label: 'Endpoint'},
                version: {type: 'string', label: 'Version'},
                responseCode: {type: 'integer', label: 'Response Code', minimum: 0, maximum: 999},
                comment: {type: 'string', label: 'Comment'}
            }
        }
    }

    public readonly id: string = 'mgcp'

    public readonly name: string = 'Media Gateway Control Protocol'

    public readonly nickname: string = 'MGCP'

    public readonly matchKeys: string[] = ['udpport:2427', 'udpport:2727']

    public match(): boolean {
        //MGCP rides on UDP ports 2427 (gateway) / 2727 (call agent) as US-ASCII text. Recognize it by the
        //first-line signature: a known verb followed by a space, or a 3-digit response code followed by a
        //space — so non-MGCP traffic on these ports falls through to raw rather than claiming an
        //un-decodable text layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'udp') return false
        if (this.#payloadLength() < 5) return false
        const lead: string = this.readBytes(0, 16, true).toString('latin1')
        //A 3-digit response code (e.g. "200 ") begins a response.
        if (/^\d{3} /.test(lead)) return true
        for (const verb of MGCP_VERBS) {
            if (lead.startsWith(verb + ' ')) return true
        }
        return false
    }

    //A leaf header — the embedded SDP body and the transaction it belongs to are a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
