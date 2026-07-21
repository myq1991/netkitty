import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Finger — the Finger User Information Protocol (RFC 1288), carried over TCP well-known port 79. A Finger
 * transaction opens with a single US-ASCII query line the client sends to the server, terminated by CR LF:
 *
 *   {C}                         — empty line: "list all users" ({U} query with no username)
 *   {username}{C}               — a {U} query naming one user, e.g. "root\r\n"
 *   /W{C} · /W {username}{C}     — the verbose ("whois") switch {W} = "/W", optionally followed by a
 *                                 username, e.g. "/W root\r\n" (a forwarding {H} form "user@host" is just
 *                                 carried inside the username text)
 *
 * MINIMAL slice (mirrors the SSH/Telnet verbatim-message pattern): the query is free-form US-ASCII text
 * with only a line ending for framing, so the structure a form needs is far poorer than the exact bytes a
 * peer sees. The ENTIRE payload is therefore the single source of truth — decoded verbatim to hex in the
 * authoritative `message` field and re-emitted byte-for-byte on encode. On top of that the first line is
 * parsed into DISPLAY-ONLY metadata: `query` (the username with any leading "/W" verbose switch and
 * surrounding whitespace stripped) and `isVerbose` (true when the line opens with "/W"). Those carry no
 * codec of their own and never reconstruct the bytes — the message owns them. So any Finger payload (an
 * empty list-all query, a username, a verbose query, a server's textual response, or a truncated
 * fragment) round-trips exactly.
 *
 * Matching rationale (NO heuristicFallback): Finger is claimed ONLY on the tcp:79 bucket. A Finger query
 * is arbitrary US-ASCII text with no distinctive off-port content signature (a bare "root\r\n" or an empty
 * "\r\n" is indistinguishable from countless other line protocols), so recognizing it relies entirely on
 * the well-known port. Joining the global content-heuristic chain would let Finger mislabel arbitrary text
 * TCP payloads on any port. Confining Finger to tcp:79 keeps that impossible; alt-port Finger is rare and
 * falls losslessly to raw. For the same reason match() does NOT gate on printable text: on the port-79
 * bucket every payload IS Finger, so any non-empty payload is kept verbatim rather than dropped to raw.
 */
export class Finger extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Finger.#schemaCache ??= Finger.#buildSchema())
    }

    /** Bytes available to this header: Finger rides on TCP, which has no per-message length. */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /**
     * Parse the first line into the display-only metadata fields. The Finger query is `[/W[ ]]username{C}`
     * where {C} is CR LF (a lone LF is tolerated); "/W" is the verbose switch. Populated on decode only —
     * these fields have no encode, so they never affect the re-emitted bytes and never mutate `message`.
     * Never throws: an empty payload yields empty query / isVerbose false.
     */
    #parseQuery(text: string): void {
        //Keep only up to the first line ending for the display parse; `message` still holds all bytes.
        let line: string = text
        const lf: number = line.indexOf('\n')
        if (lf >= 0) line = line.slice(0, lf)
        if (line.endsWith('\r')) line = line.slice(0, -1)
        //The verbose switch is the literal "/W" at the very start of the line (RFC 1288 §2.3).
        let verbose: boolean = false
        if (line.startsWith('/W')) {
            verbose = true
            line = line.slice(2)
        }
        //Strip the whitespace that separates the switch from the username (or leads a plain query).
        const query: string = line.trim()
        this.instance.isVerbose.setValue(verbose)
        this.instance.query.setValue(query)
        this.instance.summaryInfo.setValue(query ? query : 'list all')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Finger ${summaryInfo}',
            properties: {
                //Display-only metadata parsed from the first line on decode (no encode — populated by the
                //`message` field below, never read back). isVerbose flags a query opening with "/W"; query
                //is the username text with the verbose switch and surrounding whitespace removed.
                isVerbose: {type: 'boolean', label: 'Is Verbose', default: false},
                query: {type: 'string', label: 'Query', default: ''},
                //Drives the one-line summary: the query text, or 'list all' for the empty query.
                summaryInfo: {type: 'string', label: 'Summary', hidden: true, default: ''},
                //The whole raw payload is the single source of truth: decoded verbatim to hex and re-emitted
                //untouched (byte-perfect for any Finger payload). The first line is parsed into the
                //display-only metadata above, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: Finger): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseQuery('')
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseQuery(raw.toString('latin1'))
                    },
                    encode: function (this: Finger): void {
                        //Re-emit the authoritative payload verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                }
            }
        }
    }

    public readonly id: string = 'finger'

    public readonly name: string = 'Finger'

    public readonly nickname: string = 'Finger'

    //Finger is recognized ONLY on the well-known port 79 — deliberately NOT via heuristicFallback. A Finger
    //query is arbitrary US-ASCII text with no distinctive off-port content signature, so its recognition
    //depends entirely on the port bucket; joining the global heuristic chain would mislabel arbitrary text
    //TCP payloads on any port. See the class doc for the full rationale.
    public readonly matchKeys: string[] = ['tcpport:79']

    public match(): boolean {
        //Reached only on the tcp:79 bucket. Port 79 IS Finger's, so any non-empty payload over TCP is
        //claimed and kept verbatim (byte-perfect) — deliberately without a printable-text gate, so a
        //response body is never wrongly dropped to raw. An empty payload is not claimed.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        return this.#payloadLength() >= 1
    }

    //A leaf header — a Finger query/response is free-form user-information text; nothing demuxes off it.
    public readonly demuxProducers: DemuxProducer[] = []

}
