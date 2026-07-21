import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * WS-Discovery — Web Services Dynamic Discovery (OASIS, WS-Discovery 1.0/1.1), the multicast SOAP
 * protocol devices use to announce themselves and find each other on a local link. Messages are SOAP
 * 1.2 envelopes (XML) carried in UDP datagrams to the multicast group 239.255.255.250:3702 (IPv4) or
 * [FF02::C]:3702 (IPv6). The five message kinds — Hello / Bye / Probe / ProbeMatches / Resolve /
 * ResolveMatches — are distinguished only by the WS-Addressing `Action` URI inside the envelope, not by
 * any binary framing.
 *
 * Like SIP and HTTP, the message body is XML whose full internal structure (namespaces, header blocks,
 * an arbitrary SOAP body) is far richer than a form needs — and byte-exact whitespace/attribute ordering
 * is significant to some peers and to any signature. So the ENTIRE raw datagram payload is kept verbatim
 * as the authoritative `message` field (hex) and re-emitted untouched; only the WS-Addressing `Action`
 * URI is parsed on decode into display-only metadata (the full Action and its short message type). Encode
 * never reconstructs the XML from the parsed fields — it writes `message` back byte-for-byte — so any
 * conformant (or even malformed) WS-Discovery datagram round-trips exactly.
 */
export class WSDiscovery extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (WSDiscovery.#schemaCache ??= WSDiscovery.#buildSchema())
    }

    /**
     * Bytes of this header: WS-Discovery rides on UDP, so the payload is bounded by the datagram length
     * (so a retained FCS/padding is not absorbed); falls back to the rest of the packet if the UDP length
     * is implausible. Never negative.
     */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /**
     * Parse the WS-Addressing Action URI into the display-only metadata. The Action element is
     * namespace-prefixed (e.g. `<wsa:Action>` or `<a:Action>`), so the prefix is matched loosely; the
     * short message type is the last path segment of the URI (Probe / Hello / Bye / ProbeMatches / …).
     * Populated on decode only — these fields have no encode, so they never affect the re-emitted bytes.
     * Never throws: a missing Action yields empty strings.
     */
    #parseAction(text: string): void {
        const match: RegExpMatchArray | null = text.match(/<(?:[\w.-]+:)?Action\b[^>]*>([\s\S]*?)<\/(?:[\w.-]+:)?Action\s*>/)
        const action: string = match ? match[1].trim() : ''
        this.instance.action.setValue(action)
        //Short message type = last non-empty path segment of the Action URI.
        const segments: string[] = action.split('/').filter((segment: string): boolean => segment.length > 0)
        this.instance.messageType.setValue(segments.length > 0 ? segments[segments.length - 1] : '')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'WS-Discovery ${messageType}',
            properties: {
                //The whole raw datagram payload is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any WS-Discovery message). The WS-Addressing
                //Action is parsed into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: WSDiscovery): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseAction('')
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseAction(raw.toString('latin1'))
                    },
                    encode: function (this: WSDiscovery): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the WS-Addressing Action on decode (no encode —
                //populated by the message field above, never read back). action is the full Action URI;
                //messageType is its short trailing segment (Probe / Hello / Bye / …).
                action: {type: 'string', label: 'Action'},
                messageType: {type: 'string', label: 'Message Type'}
            }
        }
    }

    public readonly id: string = 'wsdiscovery'

    public readonly name: string = 'Web Services Dynamic Discovery'

    public readonly nickname: string = 'WS-Discovery'

    public readonly matchKeys: string[] = ['udpport:3702']

    public match(): boolean {
        //WS-Discovery rides on UDP port 3702 as a SOAP/XML datagram. Recognize it by the XML signature:
        //the payload's first non-whitespace byte is '<' (an XML declaration or the SOAP Envelope) — so
        //non-XML traffic on port 3702 falls through to raw rather than claiming an un-decodable layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'udp') return false
        if (this.#payloadLength() <= 0) return false
        const lead: string = this.readBytes(0, 16, true).toString('latin1').replace(/^[\s﻿]+/, '')
        return lead.startsWith('<')
    }

    //A leaf header — the SOAP envelope's internals and the discovery exchange it belongs to are a
    //higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
