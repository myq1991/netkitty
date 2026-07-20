import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** STOMP frame commands (STOMP 1.2) used only to recognize a frame's start-line. */
const STOMP_COMMANDS: string[] = ['CONNECT', 'STOMP', 'CONNECTED', 'SEND', 'SUBSCRIBE', 'UNSUBSCRIBE', 'ACK', 'NACK', 'BEGIN', 'COMMIT', 'ABORT', 'DISCONNECT', 'MESSAGE', 'RECEIPT', 'ERROR']

/**
 * STOMP — the Simple (or Streaming) Text Oriented Messaging Protocol (STOMP 1.2), a text framing for
 * message brokers, carried over TCP (well-known port 61613, the ActiveMQ default). A STOMP frame is
 * US-ASCII text: a COMMAND line, then zero or more `header:value` lines, a blank line, an optional body,
 * and a terminating NUL (0x00):
 *
 *   COMMAND{EOL}
 *   header1:value1{EOL}
 *   header2:value2{EOL}
 *   {EOL}
 *   body^@
 *
 * where {EOL} is a line feed (STOMP 1.2 also permits CR LF) and ^@ is the NUL octet. Between frames a
 * client/server may send a bare {EOL} as a heartbeat.
 *
 * Like SIP/Ident/HTTP (the verbatim-message pattern): a frame is free-form text — arbitrary header
 * ordering, header-value escaping (\c \n \r \\), and a body of any content-type whose length may be an
 * explicit `content-length` header or run to the NUL — so the exact bytes a peer sees are richer than a
 * form needs and whitespace/ordering is significant. The ENTIRE raw payload is therefore the single
 * source of truth: decoded verbatim to hex in the authoritative `message` field and re-emitted
 * byte-for-byte on encode. On top of that the frame's COMMAND line and a few common display headers
 * (destination, content-type, content-length) are parsed into DISPLAY-ONLY metadata; those carry no
 * codec of their own and never reconstruct the bytes — the message owns them. So any STOMP frame
 * round-trips exactly.
 *
 * Framing: STOMP frames are NUL-terminated and several may be pipelined in one TCP segment, but — like
 * the other text verbatim leaves (SIP/HTTP/Ident) and because TCP carries no per-message length here —
 * this terminal layer consumes to the end of the segment and keeps it as one verbatim `message`. A
 * well-formed single-frame segment round-trips byte-for-byte.
 *
 * Matching rationale (NO heuristicFallback): STOMP is claimed ONLY on the tcp:61613 bucket, and only
 * when the first line is a known STOMP command — a defensive content gate (like SIP's start-line) so
 * non-STOMP traffic on 61613 falls losslessly to raw. Joining the global content-heuristic chain would
 * risk mislabeling arbitrary text TCP payloads on any port, so selection stays port-bucketed.
 */
export class STOMP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (STOMP.#schemaCache ??= STOMP.#buildSchema())
    }

    /** Bytes available to this header: STOMP rides on TCP, which has no per-message length. */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /** The first line of the payload (up to the first LF, CR stripped), or the whole payload if none. */
    static #firstLine(text: string): string {
        const lf: number = text.indexOf('\n')
        let line: string = lf >= 0 ? text.slice(0, lf) : text
        if (line.endsWith('\r')) line = line.slice(0, -1)
        return line
    }

    /**
     * Parse the COMMAND line and a few common headers into the display-only metadata fields. The frame
     * is `COMMAND{EOL}(header:value{EOL})*{EOL}body`. Populated on decode only — these fields have no
     * encode, so they never affect the re-emitted bytes and never mutate `message`. Never throws:
     * missing tokens yield empty strings / 0.
     */
    #parse(text: string): void {
        const command: string = STOMP.#firstLine(text)
        this.instance.command.setValue(command)
        //Walk the header lines (COMMAND line already consumed) up to the blank line that ends the
        //headers; pull the common display headers. Header names are case-sensitive in STOMP 1.2.
        let destination: string = ''
        let contentType: string = ''
        let contentLength: number = 0
        const lines: string[] = text.split('\n')
        for (let i: number = 1; i < lines.length; i++) {
            let line: string = lines[i]
            if (line.endsWith('\r')) line = line.slice(0, -1)
            if (line === '') break
            const colon: number = line.indexOf(':')
            if (colon < 0) continue
            const key: string = line.slice(0, colon)
            const value: string = line.slice(colon + 1)
            if (key === 'destination' && destination === '') destination = value
            else if (key === 'content-type' && contentType === '') contentType = value
            else if (key === 'content-length' && contentLength === 0) {
                const parsed: number = parseInt(value.trim(), 10)
                if (Number.isFinite(parsed) && parsed > 0) contentLength = parsed
            }
        }
        this.instance.destination.setValue(destination)
        this.instance.contentType.setValue(contentType)
        this.instance.contentLength.setValue(contentLength)
        this.instance.summaryInfo.setValue(destination ? `${command} ${destination}` : command)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'STOMP ${summaryInfo}',
            properties: {
                //Display-only metadata parsed from the frame on decode (no encode — populated by the
                //`message` field below, never read back). command is the frame's COMMAND line;
                //destination/content-type/content-length are the common headers, present when the frame
                //carries them.
                command: {type: 'string', label: 'Command', default: ''},
                destination: {type: 'string', label: 'Destination', default: ''},
                contentType: {type: 'string', label: 'Content Type', default: ''},
                contentLength: {type: 'integer', label: 'Content Length', minimum: 0, default: 0},
                //Drives the one-line summary (COMMAND + destination when present).
                summaryInfo: {type: 'string', label: 'Summary', hidden: true, default: ''},
                //The whole raw payload is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any STOMP frame). The COMMAND line and common
                //headers are parsed into the display-only metadata above, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: STOMP): void {
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
                    encode: function (this: STOMP): void {
                        //Re-emit the authoritative payload verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                }
            }
        }
    }

    public readonly id: string = 'stomp'

    public readonly name: string = 'Simple Text Oriented Messaging Protocol'

    public readonly nickname: string = 'STOMP'

    //STOMP is recognized ONLY on the well-known port 61613 — deliberately NOT via heuristicFallback. A
    //STOMP frame is US-ASCII text; joining the global heuristic chain would mislabel arbitrary text TCP
    //payloads on any port. Confining STOMP to tcp:61613 + a command-line gate keeps that impossible;
    //alt-port STOMP is rare and falls losslessly to raw. See the class doc for the full rationale.
    public readonly matchKeys: string[] = ['tcpport:61613']

    public match(): boolean {
        //Reached only on the tcp:61613 bucket. Recognize STOMP by its start-line signature: the first
        //line (up to the first LF) is a known STOMP command — so non-STOMP traffic on 61613 (and bare
        //heartbeat newlines) falls through to raw rather than claiming an un-decodable text layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() <= 0) return false
        //Read a small lead window (long enough for the longest command + terminator) without advancing.
        const lead: string = this.readBytes(0, 16, true).toString('latin1')
        const line: string = STOMP.#firstLine(lead)
        return STOMP_COMMANDS.includes(line)
    }

    //A leaf header — a STOMP frame's body is an opaque message payload; nothing demuxes off it.
    public readonly demuxProducers: DemuxProducer[] = []

}
