import {DNS} from './DNS'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'

/**
 * LLMNR — Link-Local Multicast Name Resolution (RFC 4795). Like mDNS, the on-wire message is the
 * standard DNS message format (RFC 1035): the same 12-byte header, questions, and resource records
 * with label compression. LLMNR reinterprets two header bits that DNS already carries verbatim (the C
 * "conflict" and T "tentative" bits inside the flags word), so the inherited DNS decode/encode
 * round-trips every LLMNR message byte-perfect. Only the identity, the demux port (UDP 5355), the Info
 * summary, and a tightened match() differ. Multicast group 224.0.0.252 / ff02::1:3.
 */
export class LLMNR extends DNS {

    static #schemaCache: ProtocolJSONSchema | undefined

    //Reuse the parent DNS schema (identical wire format + closures) but relabel the Info summary.
    public get SCHEMA(): ProtocolJSONSchema {
        return (LLMNR.#schemaCache ??= {...super.SCHEMA, summary: 'LLMNR ${id} queries=${qdcount} answers=${ancount}'})
    }

    public readonly id: string = 'llmnr'

    public readonly name: string = 'Link-Local Multicast Name Resolution'

    public readonly nickname: string = 'LLMNR'

    public readonly matchKeys: string[] = ['udpport:5355']

    /**
     * LLMNR uses UDP port 5355 and never the classic DNS port 53. As UDP produces its demux keys
     * destination-port-first, reject any packet that carries port 53 (that is DNS) and require 5355.
     */
    public match(): boolean {
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        const srcport: number = this.prevCodecModule.instance.srcport.getValue(0)
        const dstport: number = this.prevCodecModule.instance.dstport.getValue(0)
        if (srcport === 53 || dstport === 53) return false
        return srcport === 5355 || dstport === 5355
    }

}
