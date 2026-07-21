import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * StatsD — the Etsy/Graphite metrics line protocol, carried as plain text over UDP (well-known port
 * 8125). A datagram carries one or more newline-separated metrics, each of the form
 * `name:value|type[|@sampleRate]` (e.g. `gorets:1|c` a counter, `glork:320|ms` a timer). The type is a
 * short tag: `c` counter, `g` gauge, `ms` timer, `s` set, `h` histogram.
 *
 * Like Syslog/SIP/HTTP, a StatsD datagram is free-form text whose full internal structure (multiple
 * metrics, tag extensions, significant separators) is richer than a form needs, and the exact bytes are
 * authoritative. So the ENTIRE raw payload is kept verbatim as the `message` field (hex) and re-emitted
 * untouched — byte-perfect for any datagram, well-formed or not; only the FIRST metric line is parsed on
 * decode into display-only metadata (name/value/type/sampleRate). Encode never reconstructs the message
 * from the parsed fields — it writes `message` back byte-for-byte — so any StatsD datagram round-trips
 * exactly. The payload is bounded by the UDP datagram length so a retained FCS/padding is not absorbed.
 */
export class StatsD extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (StatsD.#schemaCache ??= StatsD.#buildSchema())
    }

    /**
     * Bytes of this header: bounded by the UDP datagram length (payload = udpLength - 8) so a retained
     * Ethernet FCS / padding is not absorbed into the message; never negative.
     */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /** The first line of the payload (up to the first newline, or the whole payload if none). */
    static #firstLine(text: string): string {
        const idx: number = text.indexOf('\n')
        return idx >= 0 ? text.slice(0, idx) : text
    }

    /**
     * Parse the first metric line into display-only metadata. Format: `name:value|type[|@rate]`.
     * Populated on decode only — these fields have no encode, so they never affect the re-emitted bytes.
     * Never throws: missing tokens yield empty strings / 0.
     */
    #parseFirstMetric(text: string): void {
        const line: string = StatsD.#firstLine(text).replace(/\r$/, '')
        const colon: number = line.indexOf(':')
        const name: string = colon >= 0 ? line.slice(0, colon) : line
        const rest: string = colon >= 0 ? line.slice(colon + 1) : ''
        const fields: string[] = rest.split('|')
        this.instance.metricName.setValue(name)
        this.instance.metricValue.setValue(fields[0] ? fields[0] : '')
        this.instance.metricType.setValue(fields.length > 1 && fields[1] ? fields[1] : '')
        //An optional sampling-rate field is "@<rate>" (counters, RFC-less convention). Keep the raw text.
        let sampleRate: string = ''
        for (let i: number = 2; i < fields.length; i++) {
            if (fields[i] && fields[i].startsWith('@')) {
                sampleRate = fields[i].slice(1)
                break
            }
        }
        this.instance.sampleRate.setValue(sampleRate)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'StatsD ${metricName}|${metricType}',
            properties: {
                //The whole raw payload is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any datagram). The first metric line is parsed
                //into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: StatsD): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseFirstMetric('')
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseFirstMetric(raw.toString('latin1'))
                    },
                    encode: function (this: StatsD): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the first metric line on decode (no encode — populated
                //by the message field above, never read back). sampleRate is empty when absent.
                metricName: {type: 'string', label: 'Metric Name'},
                metricValue: {type: 'string', label: 'Metric Value'},
                metricType: {type: 'string', label: 'Metric Type'},
                sampleRate: {type: 'string', label: 'Sample Rate'}
            }
        }
    }

    public readonly id: string = 'statsd'

    public readonly name: string = 'StatsD Metrics Protocol'

    public readonly nickname: string = 'StatsD'

    //StatsD rides on UDP, well-known port 8125. Port-bucketed only (no heuristicFallback): the line
    //format has no distinctive magic, so claiming it off-port would risk stealing arbitrary UDP text.
    public readonly matchKeys: string[] = ['udpport:8125']

    public match(): boolean {
        //StatsD rides on UDP port 8125 as plain text. Recognize it by the metric-line signature —
        //`name:value|type` (a colon, then a value, then a pipe followed by a type letter) — so non-StatsD
        //traffic on 8125 falls through to raw rather than claiming an un-decodable text layer. match()
        //does not affect the re-emitted bytes; only the message field (verbatim) does.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.#payloadLength() <= 0) return false
        const lead: string = this.readBytes(0, 64, true).toString('latin1')
        const line: string = StatsD.#firstLine(lead)
        //name (no colon/pipe/newline) ':' value (no pipe/newline) '|' type-letter.
        return /^[^:|\r\n]+:[^|\r\n]*\|[a-zA-Z]/.test(line)
    }

    //A leaf header — a datagram may carry several metrics, but they are all held verbatim in `message`.
    public readonly demuxProducers: DemuxProducer[] = []

}
