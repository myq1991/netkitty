import {DNS} from './DNS'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'

/**
 * mDNS — Multicast DNS (RFC 6762). The on-wire message format is byte-for-byte the standard DNS message
 * (RFC 1035): the same 12-byte header, questions, and resource records with label compression. mDNS
 * only reinterprets bits that DNS already carries verbatim — the top bit of a question's QCLASS is the
 * unicast-response (QU) bit, and the top bit of a record's CLASS is the cache-flush bit — so storing
 * QCLASS/CLASS as their full 16-bit values (as the DNS codec does) preserves them automatically and the
 * whole message round-trips byte-perfect through the inherited DNS decode/encode. The only differences
 * here are the protocol identity, the demux port (UDP 5353), the Info summary, and a tightened match().
 */
export class MDNS extends DNS {

    static #schemaCache: ProtocolJSONSchema | undefined

    //Reuse the parent DNS schema (identical wire format + field closures) but relabel the Info summary
    //so an mDNS packet does not render as "DNS". Shares the `properties` closures by reference; only the
    //top-level object and its summary template differ.
    public get SCHEMA(): ProtocolJSONSchema {
        return (MDNS.#schemaCache ??= {...super.SCHEMA, summary: 'mDNS ${id} queries=${qdcount} answers=${ancount}'})
    }

    public readonly id: string = 'mdns'

    public readonly name: string = 'Multicast DNS'

    public readonly nickname: string = 'mDNS'

    public readonly matchKeys: string[] = ['udpport:5353']

    /**
     * mDNS lives on UDP port 5353 and never uses the classic DNS port 53. Because UDP produces its demux
     * keys destination-port-first, a DNS *response* (srcport 53) sent to a client that happens to use
     * ephemeral port 5353 would otherwise hit the mDNS bucket first and be mislabeled. Reject any packet
     * that carries port 53 (that is DNS, matched by the udpport:53 bucket), and require 5353 to be present.
     */
    public match(): boolean {
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        const srcport: number = this.prevCodecModule.instance.srcport.getValue(0)
        const dstport: number = this.prevCodecModule.instance.dstport.getValue(0)
        if (srcport === 53 || dstport === 53) return false
        return srcport === 5353 || dstport === 5353
    }

}
