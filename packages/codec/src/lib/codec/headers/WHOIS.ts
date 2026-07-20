import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * WHOIS — the WHOIS Protocol (RFC 3912), carried over TCP well-known port 43. WHOIS is deliberately
 * trivial on the wire: the client opens the connection and sends a single US-ASCII request line
 * `<query>\r\n` (e.g. `example.com\r\n`); the server replies with free-form US-ASCII text (the registry
 * record, terminated by the server closing the connection). There is no framing, no length prefix, and
 * no content magic in either direction — a request is just a line of text and a response is just text.
 *
 * MINIMAL slice (mirrors the SSH-identification / Telnet verbatim-message pattern): the stream has no
 * per-message structure, so the ENTIRE payload is the single source of truth — decoded verbatim to hex
 * in the authoritative `message` field and re-emitted byte-for-byte on encode. On top of that, the first
 * line of the payload is parsed into a DISPLAY-ONLY `query` field (the request domain, or the first line
 * of a response) and an `isQuery` flag (true when the whole payload is a single CR-LF-terminated line —
 * the classic request shape). Those display fields carry no codec of their own and never reconstruct the
 * bytes — the `message` owns them. So any WHOIS payload (a request line, a multi-line response record, or
 * a truncated fragment) round-trips exactly.
 *
 * Matching rationale (NO heuristicFallback): WHOIS is claimed ONLY on the tcp:43 bucket. WHOIS has NO
 * distinctive off-port content signature — a request is an arbitrary domain line and a response is
 * arbitrary text, indistinguishable from any other line-oriented TCP payload — so recognizing it relies
 * entirely on the well-known port. Joining the global content-heuristic chain would let WHOIS mislabel
 * arbitrary TCP payloads on any port. Confining WHOIS to tcp:43 keeps that impossible; alt-port WHOIS is
 * rare and falls losslessly to raw. For the same reason match() does NOT gate on printable text: on the
 * port-43 bucket every payload IS WHOIS, so any non-empty payload is kept verbatim rather than dropped.
 */
export class WHOIS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (WHOIS.#schemaCache ??= WHOIS.#buildSchema())
    }

    /** Bytes available to this header: WHOIS rides on TCP, which has no per-message length. */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /**
     * Parse the display-only metadata from the verbatim payload. `query` is the first line with its
     * trailing CR/LF stripped (the request domain, or the opening line of a response). `isQuery` is true
     * when the whole payload is exactly one CR-LF-terminated line — the classic client request shape.
     * Populated on decode only — these fields have no encode, so they never affect the re-emitted bytes
     * and never mutate `message`. Never throws: an empty or line-less payload yields an empty query.
     */
    #parseQuery(raw: Buffer): void {
        const text: string = raw.toString('latin1')
        let firstLine: string = text
        const lf: number = firstLine.indexOf('\n')
        if (lf >= 0) firstLine = firstLine.slice(0, lf)
        if (firstLine.endsWith('\r')) firstLine = firstLine.slice(0, -1)
        this.instance.query.setValue(firstLine)
        //The classic request is a single `<query>\r\n` line: exactly one line ending, at the very end.
        const isQuery: boolean = (text.endsWith('\r\n') || text.endsWith('\n')) && text.indexOf('\n') === text.length - 1
        this.instance.isQuery.setValue(isQuery)
        this.instance.summaryInfo.setValue(firstLine ? firstLine : (raw.length > 0 ? 'response' : ''))
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'WHOIS ${summaryInfo}',
            properties: {
                //Display-only metadata parsed from the verbatim payload on decode (no encode — populated
                //by the `message` field below, never read back). `query` is the first line (the request
                //domain or a response's opening line); `isQuery` flags the single-line request shape.
                isQuery: {type: 'boolean', label: 'Is Query', default: false},
                query: {type: 'string', label: 'Query', default: ''},
                //Drives the one-line summary: the first line of the payload, else 'response'.
                summaryInfo: {type: 'string', label: 'Summary', hidden: true, default: ''},
                //The whole raw payload is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any WHOIS payload). The first line is parsed into
                //the display-only metadata above, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: WHOIS): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseQuery(Buffer.alloc(0))
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseQuery(raw)
                    },
                    encode: function (this: WHOIS): void {
                        //Re-emit the authoritative payload verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                }
            }
        }
    }

    public readonly id: string = 'whois'

    public readonly name: string = 'WHOIS'

    public readonly nickname: string = 'WHOIS'

    //WHOIS is recognized ONLY on the well-known port 43 — deliberately NOT via heuristicFallback. WHOIS
    //is a line-oriented text stream with no distinctive off-port content signature (a request is an
    //arbitrary domain and a response is arbitrary text), so its recognition depends entirely on the port
    //bucket; joining the global heuristic chain would mislabel arbitrary TCP traffic. See the class doc.
    public readonly matchKeys: string[] = ['tcpport:43']

    public match(): boolean {
        //Reached only on the tcp:43 bucket. Port 43 IS WHOIS's, so any non-empty payload over TCP is
        //claimed and kept verbatim (byte-perfect) — deliberately without a printable-text gate, so a
        //non-ASCII fragment is never wrongly dropped to raw. An empty payload is not claimed.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        return this.#payloadLength() >= 1
    }

    //A leaf header — a WHOIS request/response is the application data itself; nothing demuxes off it.
    public readonly demuxProducers: DemuxProducer[] = []

}
