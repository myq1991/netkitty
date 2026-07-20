import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * XMPP — the Extensible Messaging and Presence Protocol (RFC 6120), the XML-streaming protocol behind
 * Jabber and many IM/presence systems. It rides over TCP: client-to-server on port 5222, server-to-server
 * on port 5269. Unlike a request/response protocol, an XMPP session is a pair of open-ended XML streams —
 * each peer opens a `<stream:stream>` root element and then emits a sequence of "stanzas" (`<message>`,
 * `<presence>`, `<iq>`) as child elements until the stream is closed with `</stream:stream>`. A single
 * captured packet therefore carries an arbitrary FRAGMENT of that XML text: the stream preamble
 * (`<?xml version='1.0'?><stream:stream …>`), one or more whole stanzas, or even a partial element split
 * across TCP segments.
 *
 * Like SIP and HTTP, the payload is text whose full internal structure (namespaces, arbitrary nested
 * elements, significant whitespace, entity encoding) is far richer than a form needs, and byte ordering /
 * whitespace is significant to the XML stream parser on the other end. So the ENTIRE raw payload is kept
 * verbatim as the authoritative `message` field (hex) and re-emitted untouched; only lightweight
 * display-only metadata (the first element's tag name, whether it is a stream header, whether an XML
 * declaration is present) is parsed on decode. Encode never reconstructs the XML from the metadata — it
 * writes `message` back byte-for-byte — so any conformant (or even malformed) XMPP fragment round-trips
 * exactly.
 *
 * Note: XMPP stanzas can span multiple TCP segments and TLS/SASL negotiation (STARTTLS) switches the
 * stream to ciphertext mid-session; reassembly and post-STARTTLS decryption are out of scope. This
 * single-segment codec keeps whatever XML bytes are present in the current segment verbatim, which is
 * byte-perfect for the single-packet case.
 */
export class XMPP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (XMPP.#schemaCache ??= XMPP.#buildSchema())
    }

    /**
     * Bytes of this header: XMPP rides on TCP, which has no per-message length. Bound the payload by the
     * enclosing IP datagram (IP total length) so a short XML fragment does not absorb Ethernet minimum-frame
     * padding; fall back to the rest of the captured segment when no IP layer is present. Segment reassembly
     * is out of scope (see class doc).
     */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        //Walk back to the enclosing IP layer (prevCodecModule is the TCP header) to cap at the IP payload.
        for (let i: number = this.prevCodecModules.length - 1; i >= 0; i--) {
            const module: any = this.prevCodecModules[i]
            if (module.id === 'ipv4') {
                const ipEnd: number = module.startPos + module.instance.length.getValue(0)
                const bounded: number = ipEnd - this.startPos
                if (bounded >= 0 && bounded < available) available = bounded
                break
            }
            if (module.id === 'ipv6') {
                const ipEnd: number = module.startPos + module.length + module.instance.plen.getValue(0)
                const bounded: number = ipEnd - this.startPos
                if (bounded >= 0 && bounded < available) available = bounded
                break
            }
        }
        return available < 0 ? 0 : available
    }

    /**
     * Parse the fragment head into the display-only metadata fields. Populated on decode only — these
     * fields have no encode, so they never affect the re-emitted bytes and never mutate `message`. Never
     * throws: a fragment with no recognizable start tag yields an empty rootElement.
     */
    #parseMetadata(text: string): void {
        //Skip an optional leading XML declaration (`<?xml … ?>`), then find the first element start tag.
        const declaration: RegExpMatchArray | null = text.match(/^\s*<\?xml\b[^>]*\?>/)
        const rest: string = declaration ? text.slice(declaration[0].length) : text
        //First start-tag name: `<` then the tag name up to whitespace, `>` or `/` (closing tags start
        //with `/`, excluded from the first char class, so `</stream:stream>` is not matched as a name).
        const element: RegExpMatchArray | null = rest.match(/<([^\s>/!?][^\s>/]*)/)
        const name: string = element ? element[1] : ''
        this.instance.rootElement.setValue(name)
        this.instance.isStreamHeader.setValue(name === 'stream:stream')
        this.instance.hasXmlDeclaration.setValue(!!declaration)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'XMPP ${rootElement}',
            properties: {
                //The whole raw payload is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any XMPP fragment). The fragment head is parsed
                //into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: XMPP): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseMetadata('')
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseMetadata(raw.toString('latin1'))
                    },
                    encode: function (this: XMPP): void {
                        //Re-emit the authoritative payload verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the fragment head on decode (no encode — populated by the
                //message field above, never read back). rootElement is the first element's tag name (e.g.
                //'stream:stream', 'message', 'iq', 'presence'); isStreamHeader flags the stream preamble;
                //hasXmlDeclaration flags a leading `<?xml … ?>`.
                rootElement: {type: 'string', label: 'Root Element'},
                isStreamHeader: {type: 'boolean', label: 'Is Stream Header'},
                hasXmlDeclaration: {type: 'boolean', label: 'Has XML Declaration'}
            }
        }
    }

    public readonly id: string = 'xmpp'

    public readonly name: string = 'Extensible Messaging and Presence Protocol'

    public readonly nickname: string = 'XMPP'

    //Client-to-server (5222) and server-to-server (5269) TCP ports. Port-bucket dispatch only, NO
    //heuristicFallback: an XML fragment beginning with '<' is far too weak a signature to claim arbitrary
    //TCP traffic off these ports, so XMPP is recognized solely on 5222/5269 (matching the SIP precedent
    //for a generic text protocol).
    public readonly matchKeys: string[] = ['tcpport:5222', 'tcpport:5269']

    public match(): boolean {
        //XMPP rides on TCP ports 5222/5269 as an XML text stream. Beyond the port bucket, require the
        //first non-whitespace byte of the fragment to be '<' (an XML declaration or element start) so
        //non-XML traffic on these ports — e.g. a TLS record after STARTTLS (leading 0x16) — falls through
        //to raw rather than claiming an un-decodable text layer. Guard on the transport-payload length
        //(not the whole frame remainder) so Ethernet padding is not mistaken for a fragment.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() <= 0) return false
        const lead: string = this.readBytes(0, 16, true).toString('latin1')
        return lead.replace(/^\s+/, '').startsWith('<')
    }

    //A leaf header — the XML stanza tree and the stream session it belongs to are a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
