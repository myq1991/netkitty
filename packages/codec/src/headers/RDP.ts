import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'

/**
 * RDP — Remote Desktop Protocol (MS-RDPBCGR), specifically the X.224 Negotiation that opens every RDP
 * connection, carried in the user data of a COTP Connection Request / Connection Confirm (over
 * TPKT/tcp:3389). The 8-byte structure is: a 1-byte Type (0x01 Negotiation Request, 0x02 Negotiation
 * Response, 0x03 Negotiation Failure), a 1-byte Flags, a 2-byte little-endian Length (always 8), and a
 * 4-byte little-endian bitmask — the requested/selected security protocols (0x00 standard RDP, 0x01 TLS,
 * 0x02 CredSSP/HYBRID, 0x08 RDSTLS, …).
 *
 * This is the single-packet-identifiable part of RDP; the subsequent MCS/T.125 data phase (over COTP DT)
 * is a multi-layer sub-stack left for later. A cookie/routing-token prefix (ASCII "Cookie: …\r\n") that
 * may precede the Negotiation in some Connection Requests is not handled here (such a CR falls to raw).
 * The Negotiation round-trips byte-for-byte.
 */
export class RDP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (RDP.#schemaCache ??= RDP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'RDP-Neg type=${negotiationType} protocols=${requestedProtocols}',
            properties: {
                //0x01 Negotiation Request, 0x02 Response, 0x03 Failure.
                negotiationType: this.fieldUInt('negotiationType', 0, 1, 'Negotiation Type'),
                flags: this.fieldUInt('flags', 1, 1, 'Flags'),
                //2-byte LITTLE-ENDIAN length — always 8 for the Negotiation. Honored verbatim.
                length: {
                    type: 'integer', label: 'Length', minimum: 0, maximum: 65535,
                    decode: function (this: RDP): void {
                        const bytes: Buffer = this.readBytes(2, 2)
                        this.instance.length.setValue((bytes[0] | (bytes[1] << 8)) & 0xffff)
                    },
                    encode: function (this: RDP): void {
                        let value: number = this.instance.length.getValue(8)
                        if (value > 65535) value = 65535
                        if (value < 0) value = 0
                        this.writeBytes(2, Buffer.from([value & 0xff, (value >> 8) & 0xff]))
                    }
                },
                //4-byte LITTLE-ENDIAN protocol bitmask (RDP/TLS/CredSSP/RDSTLS). >>> 0 keeps it unsigned.
                requestedProtocols: {
                    type: 'integer', label: 'Requested Protocols', minimum: 0, maximum: 4294967295,
                    decode: function (this: RDP): void {
                        const b: Buffer = this.readBytes(4, 4)
                        this.instance.requestedProtocols.setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
                    },
                    encode: function (this: RDP): void {
                        let value: number = this.instance.requestedProtocols.getValue(0)
                        if (value > 4294967295) value = 4294967295
                        if (value < 0) value = 0
                        this.writeBytes(4, Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff]))
                    }
                }
            }
        }
    }

    public readonly id: string = 'rdp'

    public readonly name: string = 'Remote Desktop Protocol'

    public readonly nickname: string = 'RDP'

    //A content-heuristic child of COTP (unkeyed), selected by the X.224 Negotiation signature.
    public readonly matchKeys: string[] = []

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        //Rides in COTP CR/CC user data. The Negotiation is a strong signature: an 8-byte structure whose
        //Type is 0x01/0x02/0x03 and whose little-endian Length field is exactly 8 (byte 2 = 0x08, byte
        //3 = 0x00) — distinctive enough to separate it from ISO-Session/other COTP payloads without a
        //port gate.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'cotp') return false
        if (this.packet.length - this.startPos < 8) return false
        const header: Buffer = this.readBytes(0, 4, true)
        const type: number = header[0]
        if (type !== 0x01 && type !== 0x02 && type !== 0x03) return false
        return header[2] === 0x08 && header[3] === 0x00
    }

    //A leaf for this slice — the MCS/T.125 data phase is a separate sub-stack.
    public readonly demuxProducers: DemuxProducer[] = []

}
