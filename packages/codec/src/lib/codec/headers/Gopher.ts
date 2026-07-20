import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** The Gopher well-known TCP port (RFC 1436). */
const GOPHER_PORT: number = 70

/**
 * Gopher — the Internet Gopher Protocol (RFC 1436), carried over TCP well-known port 70. A transaction
 * is US-ASCII text:
 *
 *   REQUEST  (client → server):  "<selector>{C}"                       e.g. "/rfc/rfc1436.txt\r\n"
 *                            or  "<selector>{TAB}<search>{C}"          (a type-7 index-search query)
 *                                {C} is CR LF. The empty selector requests the root menu ("\r\n").
 *   RESPONSE (server → client):  a series of directory items, each a Gopher menu line
 *                                "<type><display>{TAB}<selector>{TAB}<host>{TAB}<port>{C}", the whole
 *                                listing terminated by a lone "." line (".\r\n"); or, for a text item,
 *                                the file body terminated the same way.
 *
 * MINIMAL slice (mirrors the Finger/Ident/SIP/HTTP verbatim-message pattern): a Gopher message is
 * free-form US-ASCII framed only by CR LF and a menu grammar whose display/selector/host fields MAY carry
 * almost any octet, and whitespace/line ordering is significant to peers. The ENTIRE payload is therefore
 * the single source of truth — decoded verbatim to hex in the authoritative `message` field and
 * re-emitted byte-for-byte on encode. On top of that the first line is parsed into DISPLAY-ONLY metadata:
 * whether the transaction is a request or a response (decided by the TCP port direction — dst 70 is a
 * request, src 70 a response), the request selector and optional type-7 search term, and whether the
 * payload is terminated by the "." end-of-transmission line. Those metadata carry no codec of their own
 * and never reconstruct the bytes — the message owns them. So any Gopher payload (a selector request, a
 * menu response, a text body, or a truncated fragment) round-trips exactly.
 *
 * Matching rationale (NO heuristicFallback): Gopher is claimed ONLY on the tcp:70 bucket. A request line
 * is arbitrary US-ASCII text with no distinctive off-port content signature, so recognizing it relies
 * entirely on the well-known port; joining the global content-heuristic chain would mislabel arbitrary
 * text TCP payloads on any port. Confining Gopher to tcp:70 keeps that impossible; alt-port Gopher is rare
 * and falls losslessly to raw. As the terminal verbatim layer it consumes to the end of the segment (like
 * Finger/Ident/HTTP) so a well-formed frame round-trips byte-for-byte.
 */
export class Gopher extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Gopher.#schemaCache ??= Gopher.#buildSchema())
    }

    /** Bytes available to this header: Gopher rides on TCP, which has no per-message length. */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /**
     * True when this transaction is a client request (TCP destination port 70), false for a server
     * response (source port 70). Read from the parent TCP layer for display only; when neither port is 70
     * (an alt-port capture that still reached this bucket via a custom match) it defaults to a request.
     */
    #isRequestDirection(): boolean {
        const tcp: any = this.prevCodecModule
        if (!tcp) return true
        const dstport: number = tcp.instance.dstport.getValue(0)
        const srcport: number = tcp.instance.srcport.getValue(0)
        if (srcport === GOPHER_PORT && dstport !== GOPHER_PORT) return false
        return true
    }

    /**
     * Parse the first line into the display-only metadata fields. A request line is
     * `<selector>[{TAB}<search>]{C}`; a response is a menu/text body terminated by a lone "." line.
     * Populated on decode only — these fields have no encode, so they never affect the re-emitted bytes
     * and never mutate `message`. Never throws: missing tokens yield empty strings / 0.
     */
    #parse(text: string): void {
        const isRequest: boolean = this.#isRequestDirection()
        this.instance.isRequest.setValue(isRequest)
        //Isolate the first line (up to the first CR LF, or a lone LF); `message` still holds all bytes.
        let firstLine: string = text
        const lf: number = firstLine.indexOf('\n')
        if (lf >= 0) firstLine = firstLine.slice(0, lf)
        if (firstLine.endsWith('\r')) firstLine = firstLine.slice(0, -1)
        //A Gopher payload is complete when it ends with the "." end-of-transmission line (".\r\n", or a
        //lone "." with a tolerated bare LF, or the whole payload being just ".").
        const hasTerminator: boolean = /(^|\r?\n)\.\r?\n$/.test(text) || text === '.\r\n' || text === '.\n' || text === '.'
        this.instance.hasTerminator.setValue(hasTerminator)
        if (isRequest) {
            //Request: the selector is the first line, optionally followed by a TAB + search term (type 7).
            const tab: number = firstLine.indexOf('\t')
            const selector: string = tab >= 0 ? firstLine.slice(0, tab) : firstLine
            const search: string = tab >= 0 ? firstLine.slice(tab + 1) : ''
            this.instance.selector.setValue(selector)
            this.instance.searchTerm.setValue(search)
            this.instance.itemCount.setValue(0)
            const shown: string = selector === '' ? '(root)' : selector
            this.instance.summaryInfo.setValue(search ? `request ${shown} search="${search}"` : `request ${shown}`)
            return
        }
        //Response: count the menu/text lines that precede the terminating "." line. Split on LF, drop the
        //optional trailing empty element after the last CR LF, and stop at the "." terminator line.
        this.instance.selector.setValue('')
        this.instance.searchTerm.setValue('')
        const lines: string[] = text.split('\n')
        let count: number = 0
        for (const rawLine of lines) {
            const line: string = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine
            if (line === '.') break
            if (line === '' ) continue
            count++
        }
        this.instance.itemCount.setValue(count)
        this.instance.summaryInfo.setValue(`response ${count} line${count === 1 ? '' : 's'}${hasTerminator ? '' : ' (partial)'}`)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Gopher ${summaryInfo}',
            properties: {
                //Display-only metadata parsed on decode (no encode — populated by the `message` field
                //below, never read back). isRequest is decided by the TCP port direction; selector and
                //searchTerm apply to a request; itemCount to a response; hasTerminator flags the "." end.
                isRequest: {type: 'boolean', label: 'Is Request', default: false},
                selector: {type: 'string', label: 'Selector', default: ''},
                searchTerm: {type: 'string', label: 'Search Term', default: ''},
                itemCount: {type: 'integer', label: 'Item Count', minimum: 0, default: 0},
                hasTerminator: {type: 'boolean', label: 'Has Terminator', default: false},
                //Drives the one-line summary (request selector / response line count).
                summaryInfo: {type: 'string', label: 'Summary', hidden: true, default: ''},
                //The whole raw payload is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any Gopher payload). The first line is parsed into
                //the display-only metadata above, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: Gopher): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parse('')
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parse(raw.toString('latin1'))
                    },
                    encode: function (this: Gopher): void {
                        //Re-emit the authoritative payload verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                }
            }
        }
    }

    public readonly id: string = 'gopher'

    public readonly name: string = 'Internet Gopher Protocol'

    public readonly nickname: string = 'Gopher'

    //Gopher is recognized ONLY on the well-known port 70 — deliberately NOT via heuristicFallback. A
    //request/response line is arbitrary US-ASCII text with no distinctive off-port content signature, so
    //its recognition depends entirely on the port bucket; joining the global heuristic chain would
    //mislabel arbitrary text TCP payloads on any port. See the class doc for the full rationale.
    public readonly matchKeys: string[] = ['tcpport:70']

    public match(): boolean {
        //Reached only on the tcp:70 bucket. Port 70 IS Gopher's, so any non-empty payload over TCP is
        //claimed and kept verbatim (byte-perfect) — deliberately without a printable-text gate, so a
        //binary text/menu body is never wrongly dropped to raw. An empty payload (a bare ACK) is not
        //claimed.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        return this.#payloadLength() >= 1
    }

    //A leaf header — a Gopher request/response is a single free-form text transaction; nothing demuxes
    //off it.
    public readonly demuxProducers: DemuxProducer[] = []

}
