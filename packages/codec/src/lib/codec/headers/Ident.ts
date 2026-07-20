import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Ident — the Identification Protocol (RFC 1413), carried over TCP well-known port 113. A single
 * US-ASCII line, terminated by CR LF, is exchanged in each direction:
 *
 *   QUERY  (client → server):  "<server-port> , <client-port>{C}"
 *                              e.g. "6193, 23\r\n" — asks the ident server who owns the connection
 *                              whose remote/local TCP ports are server-port and client-port.
 *   REPLY  (server → client):  "<server-port> , <client-port> : USERID : <opsys> : <username>{C}"
 *                          or  "<server-port> , <client-port> : ERROR  : <error-type>{C}"
 *                              e.g. "6193, 23 : USERID : UNIX : stjohns\r\n"
 *                              or   "6193, 23 : ERROR : NO-USER\r\n"
 *
 * MINIMAL slice (mirrors the Finger/SIP/HTTP verbatim-message pattern): the line is free-form US-ASCII
 * with only CR LF for framing and a username field that MAY carry almost any octet, so the exact bytes a
 * peer sees are richer than a form needs. The ENTIRE payload is therefore the single source of truth —
 * decoded verbatim to hex in the authoritative `message` field and re-emitted byte-for-byte on encode.
 * On top of that the first line is parsed into DISPLAY-ONLY metadata: the two port numbers, whether the
 * line is a query or a reply, the reply type (USERID / ERROR) and its USERID opsys+username or ERROR
 * error-type. Those carry no codec of their own and never reconstruct the bytes — the message owns them.
 * So any Ident payload (a query, a USERID reply, an ERROR reply, or a truncated fragment) round-trips
 * exactly.
 *
 * Matching rationale (NO heuristicFallback): Ident is claimed ONLY on the tcp:113 bucket. A query/reply
 * line is arbitrary US-ASCII text with no distinctive off-port content signature, so recognizing it
 * relies entirely on the well-known port; joining the global content-heuristic chain would mislabel
 * arbitrary text TCP payloads on any port. Confining Ident to tcp:113 keeps that impossible; alt-port
 * Ident is rare and falls losslessly to raw. As the terminal verbatim layer it consumes to the end of the
 * segment (like Finger/HTTP) so a well-formed frame round-trips byte-for-byte.
 */
export class Ident extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Ident.#schemaCache ??= Ident.#buildSchema())
    }

    /** Bytes available to this header: Ident rides on TCP, which has no per-message length. */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /** Parse a decimal TCP port for display, clamped to [0, 65535] (never throws; non-numeric → 0). */
    static #clampPort(text: string | undefined): number {
        const value: number = parseInt((text ? text : '').trim(), 10)
        if (!Number.isFinite(value)) return 0
        return value < 0 ? 0 : value > 65535 ? 65535 : value
    }

    /**
     * Parse the first line into the display-only metadata fields. The line is
     * `<server-port> , <client-port>[ : <resp-type> : ...]{C}` where {C} is CR LF (a lone LF is
     * tolerated). Populated on decode only — these fields have no encode, so they never affect the
     * re-emitted bytes and never mutate `message`. Never throws: missing tokens yield 0 / empty strings.
     */
    #parse(text: string): void {
        //Keep only up to the first line ending for the display parse; `message` still holds all bytes.
        let line: string = text
        const lf: number = line.indexOf('\n')
        if (lf >= 0) line = line.slice(0, lf)
        if (line.endsWith('\r')) line = line.slice(0, -1)
        //Fields are colon-separated; the first field is "<server-port> , <client-port>".
        const parts: string[] = line.split(':')
        const ports: string[] = (parts[0] ? parts[0] : '').split(',')
        const serverPort: number = Ident.#clampPort(ports[0])
        const clientPort: number = Ident.#clampPort(ports[1])
        this.instance.serverPort.setValue(serverPort)
        this.instance.clientPort.setValue(clientPort)
        if (parts.length <= 1) {
            //A query carries only the two ports (no ":" reply structure).
            this.instance.isQuery.setValue(true)
            this.instance.responseType.setValue('')
            this.instance.opsys.setValue('')
            this.instance.userId.setValue('')
            this.instance.errorType.setValue('')
            this.instance.summaryInfo.setValue(`query ${serverPort},${clientPort}`)
            return
        }
        this.instance.isQuery.setValue(false)
        const responseType: string = (parts[1] ? parts[1] : '').trim()
        this.instance.responseType.setValue(responseType)
        if (responseType === 'USERID') {
            //USERID : <opsys>[, <charset>] : <username> — the username is the remainder (it MAY itself
            //contain ':'), so rejoin the trailing fields rather than taking a single token.
            const opsys: string = (parts[2] ? parts[2] : '').trim()
            const userId: string = parts.length > 3 ? parts.slice(3).join(':').trim() : ''
            this.instance.opsys.setValue(opsys)
            this.instance.userId.setValue(userId)
            this.instance.errorType.setValue('')
            this.instance.summaryInfo.setValue(`USERID ${userId}`)
            return
        }
        if (responseType === 'ERROR') {
            const errorType: string = parts.length > 2 ? parts.slice(2).join(':').trim() : ''
            this.instance.opsys.setValue('')
            this.instance.userId.setValue('')
            this.instance.errorType.setValue(errorType)
            this.instance.summaryInfo.setValue(`ERROR ${errorType}`)
            return
        }
        //An unknown reply type is still a reply — keep its ports and label, drop the type-specific fields.
        this.instance.opsys.setValue('')
        this.instance.userId.setValue('')
        this.instance.errorType.setValue('')
        this.instance.summaryInfo.setValue(responseType ? responseType : `${serverPort},${clientPort}`)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Ident ${summaryInfo}',
            properties: {
                //Display-only metadata parsed from the first line on decode (no encode — populated by the
                //`message` field below, never read back). isQuery distinguishes the client query from the
                //server reply; responseType/opsys/userId apply to a USERID reply, errorType to an ERROR
                //reply. The two ports are present in both directions.
                serverPort: {type: 'integer', label: 'Server Port', minimum: 0, maximum: 65535, default: 0},
                clientPort: {type: 'integer', label: 'Client Port', minimum: 0, maximum: 65535, default: 0},
                isQuery: {type: 'boolean', label: 'Is Query', default: false},
                responseType: {type: 'string', label: 'Response Type', default: ''},
                opsys: {type: 'string', label: 'Operating System', default: ''},
                userId: {type: 'string', label: 'User ID', default: ''},
                errorType: {type: 'string', label: 'Error Type', default: ''},
                //Drives the one-line summary (query ports / USERID username / ERROR error-type).
                summaryInfo: {type: 'string', label: 'Summary', hidden: true, default: ''},
                //The whole raw payload is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any Ident payload). The first line is parsed into
                //the display-only metadata above, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: Ident): void {
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
                    encode: function (this: Ident): void {
                        //Re-emit the authoritative payload verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                }
            }
        }
    }

    public readonly id: string = 'ident'

    public readonly name: string = 'Identification Protocol'

    public readonly nickname: string = 'Ident'

    //Ident is recognized ONLY on the well-known port 113 — deliberately NOT via heuristicFallback. A
    //query/reply line is arbitrary US-ASCII text with no distinctive off-port content signature, so its
    //recognition depends entirely on the port bucket; joining the global heuristic chain would mislabel
    //arbitrary text TCP payloads on any port. See the class doc for the full rationale.
    public readonly matchKeys: string[] = ['tcpport:113']

    public match(): boolean {
        //Reached only on the tcp:113 bucket. Port 113 IS Ident's, so any non-empty payload over TCP is
        //claimed and kept verbatim (byte-perfect) — deliberately without a printable-text gate, so a
        //server reply body is never wrongly dropped to raw. An empty payload (a bare ACK) is not claimed.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        return this.#payloadLength() >= 1
    }

    //A leaf header — an Ident query/reply is a single free-form line; nothing demuxes off it.
    public readonly demuxProducers: DemuxProducer[] = []

}
