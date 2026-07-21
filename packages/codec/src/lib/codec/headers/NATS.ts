import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * NATS control operations (the client/server protocol verbs). Operations that carry arguments on the
 * control line are followed by a space; the standalone operations are followed by CRLF. The set is used
 * only to recognize the leading operation of a message. NATS treats the verbs case-insensitively.
 */
const NATS_ARG_OPS: string[] = ['CONNECT', 'INFO', 'HPUB', 'PUB', 'HMSG', 'MSG', 'SUB', 'UNSUB', '-ERR']
const NATS_SOLO_OPS: string[] = ['PING', 'PONG', '+OK']

/**
 * NATS — the client/server text protocol of the NATS messaging system, carried over TCP (well-known
 * port 4222). A NATS message is US-ASCII text: an operation verb, optional arguments on the control line
 * terminated by CRLF, and — for the publish/deliver verbs — a payload body also terminated by CRLF. The
 * control operations are `INFO {json}`, `CONNECT {json}`, `PUB subject [reply] #bytes`,
 * `HPUB ...`, `SUB subject [queue] sid`, `UNSUB sid [max]`, `MSG subject sid [reply] #bytes`,
 * `HMSG ...`, `PING`, `PONG`, `+OK`, and `-ERR message`.
 *
 * Like SIP/HTTP, the message body is text whose full internal structure (arbitrary JSON options, subject
 * hierarchies, header blocks, binary-safe payloads, significant whitespace) is far richer than a form
 * needs, and TCP may coalesce or split messages so no per-message length is authoritative. So the ENTIRE
 * raw segment is kept verbatim as the authoritative `message` field (hex) and re-emitted untouched; only
 * the leading operation and its control line are parsed on decode into display-only metadata. Encode
 * never reconstructs the message from the parsed fields — it writes `message` back byte-for-byte — so
 * any conformant (or even malformed) NATS message round-trips exactly.
 */
export class NATS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (NATS.#schemaCache ??= NATS.#buildSchema())
    }

    /**
     * Bytes of this header: NATS rides on TCP, which has no per-message length, so take the rest of the
     * segment. Reassembly / message framing across segments is out of scope (see class doc).
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
     * Parse the control line into the display-only metadata fields: the leading operation verb
     * (upper-cased, as NATS is case-insensitive) and the remaining control-line arguments. Populated on
     * decode only — these fields have no encode, so they never affect the re-emitted bytes and never
     * mutate `message`. Never throws: a missing operation yields empty strings.
     */
    #parseControlLine(text: string): void {
        const line: string = NATS.#firstLine(text)
        //The operation is the first whitespace-delimited token (space or tab); the rest is the argument
        //list (JSON for INFO/CONNECT, subject/sid/#bytes for PUB/MSG/SUB, message for -ERR, or empty).
        const spaceIdx: number = line.search(/[ \t]/)
        const operation: string = spaceIdx >= 0 ? line.slice(0, spaceIdx) : line
        const args: string = spaceIdx >= 0 ? line.slice(spaceIdx + 1) : ''
        this.instance.operation.setValue(operation.toUpperCase())
        this.instance.controlArguments.setValue(args)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'NATS ${operation}',
            properties: {
                //The whole raw segment is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any NATS message). The control line is parsed into
                //the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: NATS): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseControlLine('')
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseControlLine(raw.toString('latin1'))
                    },
                    encode: function (this: NATS): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the control line on decode (no encode — populated by the
                //message field above, never read back). operation is the leading verb (upper-cased);
                //controlArguments is the remainder of the control line (empty for PING/PONG/+OK).
                operation: {type: 'string', label: 'Operation'},
                controlArguments: {type: 'string', label: 'Arguments'}
            }
        }
    }

    public readonly id: string = 'nats'

    public readonly name: string = 'NATS Client Protocol'

    public readonly nickname: string = 'NATS'

    public readonly matchKeys: string[] = ['tcpport:4222']

    public match(): boolean {
        //NATS rides on TCP port 4222 as US-ASCII text. Recognize it by the operation signature: a known
        //argument-carrying verb followed by a space, or a standalone verb followed by CRLF — so non-NATS
        //traffic on port 4222 falls through to raw rather than claiming an un-decodable text layer. The
        //verbs are matched case-insensitively (NATS is case-insensitive). No heuristicFallback: selection
        //stays strictly port-bucketed like the other text TCP payload codecs.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() <= 0) return false
        const lead: string = this.readBytes(0, 12, true).toString('latin1').toUpperCase()
        for (const op of NATS_ARG_OPS) {
            if (lead.startsWith(op + ' ')) return true
        }
        for (const op of NATS_SOLO_OPS) {
            if (lead.startsWith(op + '\r')) return true
        }
        return false
    }

    //A leaf header — the NATS payload body and the subscription/exchange it belongs to are higher-layer
    //concerns; the raw message is kept verbatim.
    public readonly demuxProducers: DemuxProducer[] = []

}
