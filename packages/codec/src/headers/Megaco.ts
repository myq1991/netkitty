import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Megaco / H.248 (RFC 3525) — the Media Gateway Control protocol by which a Media Gateway Controller
 * commands Media Gateways for VoIP, the ITU-T/IETF successor to MGCP. This codec handles the text
 * (ABNF) encoding carried over UDP (well-known ports 2944 text / 2945 secure-text); the alternative
 * binary ASN.1/BER encoding is a separate wire format and out of scope here.
 *
 * A text message begins with a header line `MEGACO/version SP mId` (the start token "MEGACO" or its
 * short form "!", a slash, the protocol version, then the message identifier — an [ip]:port, domain
 * name, device name or MTP address), followed by one or more Transaction blocks (`Transaction = id {
 * Context = ... { commands } }`).
 *
 * Like SIP, MGCP and HTTP, the message body is text whose full internal structure (nested
 * transaction/context/command/descriptor blocks, significant whitespace and token ordering) is far
 * richer than a form needs. So the ENTIRE raw message is kept verbatim as the authoritative `message`
 * field (hex) and re-emitted untouched; only the header line is parsed on decode into display-only
 * metadata (start token / version / message identifier). Encode never reconstructs the message from
 * the parsed fields — it writes `message` back byte-for-byte — so any conformant (or even malformed)
 * Megaco message round-trips exactly.
 */
export class Megaco extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Megaco.#schemaCache ??= Megaco.#buildSchema())
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

    /** The first line of the message (up to the first CR or LF, or the whole payload if neither). */
    static #firstLine(text: string): string {
        let end: number = text.length
        for (let i: number = 0; i < text.length; i++) {
            const code: number = text.charCodeAt(i)
            if (code === 0x0d || code === 0x0a) {
                end = i
                break
            }
        }
        return text.slice(0, end)
    }

    /**
     * Parse the header line into the display-only metadata fields. The line is
     * `startToken/version SP mId` (e.g. "MEGACO/1 [123.123.123.4]:55555"). Populated on decode only —
     * these fields have no encode, so they never affect the re-emitted bytes. Never throws: a missing
     * token yields an empty string, a non-numeric version yields 0.
     */
    #parseHeaderLine(text: string): void {
        const line: string = Megaco.#firstLine(text).trim()
        //Split the leading "startToken/version" token from the message identifier on the first space.
        const spaceIdx: number = line.indexOf(' ')
        const head: string = spaceIdx >= 0 ? line.slice(0, spaceIdx) : line
        const mId: string = spaceIdx >= 0 ? line.slice(spaceIdx + 1).trim() : ''
        const slashIdx: number = head.indexOf('/')
        const token: string = slashIdx >= 0 ? head.slice(0, slashIdx) : head
        const versionText: string = slashIdx >= 0 ? head.slice(slashIdx + 1) : ''
        this.instance.startToken.setValue(token)
        //Kept as the raw digit string (display-only), not a bounded integer: RFC 3525 versions are an
        //unbounded 1*DIGIT, so a large value like "9999999999" must round-trip (the message hex is the
        //authoritative source; encode never reads this field) without Ajv rejecting it on re-encode.
        this.instance.version.setValue(versionText)
        this.instance.messageId.setValue(mId)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Megaco/${version} ${messageId}',
            properties: {
                //The whole raw message is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any Megaco message). The header line is parsed
                //into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: Megaco): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseHeaderLine('')
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseHeaderLine(raw.toString('latin1'))
                    },
                    encode: function (this: Megaco): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the header line on decode (no encode — populated by the
                //message field above, never read back). startToken is "MEGACO" (or "!" short form),
                //version is the protocol version, messageId is the message identifier (mId).
                startToken: {type: 'string', label: 'Start Token'},
                version: {type: 'string', label: 'Version'},
                messageId: {type: 'string', label: 'Message Identifier'}
            }
        }
    }

    public readonly id: string = 'megaco'

    public readonly name: string = 'Media Gateway Control Protocol (H.248/Megaco)'

    public readonly nickname: string = 'Megaco'

    public readonly matchKeys: string[] = ['udpport:2944', 'udpport:2945']

    public match(): boolean {
        //Megaco text encoding rides on UDP ports 2944 (text) / 2945 (secure text) as text. Recognize it
        //by the header-line signature: the start token "MEGACO/" or its short form "!/" (case-insensitive
        //start token) — so non-Megaco traffic on these ports falls through to raw rather than claiming an
        //un-decodable text layer. Leading whitespace (LWSP) before the token is tolerated.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'udp') return false
        if (this.#payloadLength() < 3) return false
        const lead: string = this.readBytes(0, 16, true).toString('latin1').replace(/^[\s]+/, '')
        const upper: string = lead.toUpperCase()
        return upper.startsWith('MEGACO/') || lead.startsWith('!/')
    }

    //A leaf header — the nested transaction/context/command/descriptor structure and the transaction it
    //belongs to are a higher-layer concern; the verbatim message preserves it byte-for-byte.
    public readonly demuxProducers: DemuxProducer[] = []

}
