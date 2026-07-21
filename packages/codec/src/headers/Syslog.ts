import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'

/**
 * Syslog — the BSD/IETF system logging protocol (RFC 3164 / RFC 5424) carried over UDP port 514. A
 * message is text: an optional priority value `<PRI>` (a decimal number in angle brackets, where
 * PRI = facility*8 + severity) followed by the message body. The body's internal structure differs
 * between RFC 3164 (loose: timestamp + host + tag + text) and RFC 5424 (version + timestamp + host +
 * app + procid + msgid + structured-data + msg), so it is kept verbatim as `message` — byte-perfect
 * for either format — with only the PRI split into the facility/severity it encodes (for display).
 */
export class Syslog extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Syslog.#schemaCache ??= Syslog.#buildSchema())
    }

    /** The payload text bounded by the UDP datagram length (so a retained FCS/padding is not absorbed). */
    #payloadText(): string {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        if (available <= 0) return ''
        return this.readBytes(0, available).toString('latin1')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Syslog <${pri}> ${message}',
            properties: {
                //The whole text message is parsed/emitted here; the fields below carry schema metadata.
                //`pri` is present only when the message begins with a well-formed <PRI>.
                pri: {
                    type: 'integer',
                    label: 'Priority',
                    minimum: 0,
                    maximum: 191,
                    decode: function (this: Syslog): void {
                        const text: string = this.#payloadText()
                        const match: RegExpMatchArray | null = text.match(/^<(\d{1,3})>([\s\S]*)$/)
                        //A well-formed PRI is 0..191 with no leading zeros (RFC 5424 §6.2.1). Only split
                        //it off when it is in range AND its digits re-emit identically (String(n)===text)
                        //— an out-of-range value ("<999>") or a leading-zero form ("<013>") is not a valid
                        //PRI, so the whole payload stays the message. That keeps facility/severity within
                        //their schema bounds and round-trips the exact text verbatim (encode re-emits the
                        //parsed number, which would otherwise drop leading zeros).
                        if (match && Number(match[1]) <= 191 && String(Number(match[1])) === match[1]) {
                            const pri: number = Number(match[1])
                            this.instance.pri.setValue(pri)
                            this.instance.facility.setValue(pri >> 3)
                            this.instance.severity.setValue(pri & 0x07)
                            this.instance.message.setValue(match[2])
                        } else {
                            //No (valid) priority prefix — keep the whole payload as the message.
                            this.instance.message.setValue(text)
                        }
                    },
                    encode: function (this: Syslog): void {
                        const pri: number | undefined = this.instance.pri.getValue()
                        const message: string = this.instance.message.getValue('')
                        const text: string = (pri === undefined || pri === null) ? message : `<${pri}>${message}`
                        this.writeBytes(0, Buffer.from(text, 'latin1'))
                    }
                },
                //Derived from PRI (display only; encode reconstructs PRI, not these): facility = PRI>>3,
                //severity = PRI&7.
                facility: {type: 'integer', label: 'Facility', minimum: 0, maximum: 23},
                severity: {type: 'integer', label: 'Severity', minimum: 0, maximum: 7},
                message: {type: 'string', label: 'Message'}
            }
        }
    }

    public readonly id: string = 'syslog'

    public readonly name: string = 'Syslog'

    public readonly nickname: string = 'Syslog'

    public readonly matchKeys: string[] = ['udpport:514']

    public match(): boolean {
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp'
    }

    //A leaf header — nothing demuxes above Syslog.
    public readonly demuxProducers: DemuxProducer[] = []

}
