import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'

/**
 * Time Protocol (RFC 868), TCP & UDP well-known port 37. A trivial time service: the server returns the
 * time as the number of seconds since 00:00 (midnight) 1 January 1900 GMT, in a single 32-bit big-endian
 * unsigned integer. Over TCP the client opens a connection and the server sends the 4 octets then closes;
 * over UDP the client sends an empty datagram and the server replies with a 4-octet datagram. The request
 * carries no payload, so only the 4-octet response is a Time Protocol message this codec claims.
 *
 * The whole message is exactly one field — `time`, the 32-bit seconds count — kept as a plain uint so any
 * on-wire value (including the post-2036 wrap once the counter passes 0x80000000) round-trips byte-for-byte
 * and can be re-encoded without an Ajv rejection. The response is exactly 4 octets; anything beyond is left
 * to the codec's recursion / RawData. A well-formed message round-trips byte-for-byte.
 */
export class TimeProtocol extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (TimeProtocol.#schemaCache ??= TimeProtocol.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'TIME seconds=${time}',
            properties: {
                //Seconds since 1900-01-01 00:00:00 GMT, 32-bit big-endian unsigned (RFC 868). A plain uint
                //so every on-wire value round-trips; the epoch/date rendering is UI enrichment for later.
                time: this.fieldUInt('time', 0, 4, 'Seconds since 1900-01-01 00:00:00 GMT')
            }
        }
    }

    public readonly id: string = 'timeproto'

    public readonly name: string = 'Time Protocol'

    public readonly nickname: string = 'TIME'

    public readonly matchKeys: string[] = ['tcpport:37', 'udpport:37']

    public match(): boolean {
        //Time Protocol rides on TCP/UDP port 37; the well-known port is the only signature (the payload
        //is 4 opaque bytes with no magic). The request carries no payload, so require the full 4-octet
        //response to be present — an empty request (0 bytes) is not claimed and falls through.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp' && this.prevCodecModule.id !== 'udp') return false
        return this.packet.length - this.startPos >= 4
    }

    //A leaf header — the 4-octet time value is the entire message; nothing rides above it.
    public readonly demuxProducers: DemuxProducer[] = []

}
