import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * OMRON FINS (Factory Interface Network Service), UDP port 9600. FINS is OMRON's industrial control
 * protocol for PLC access. This codec handles the UDP-encapsulated form (the TCP form prefixes a 16-byte
 * 'FINS' frame header + length and is not covered here).
 *
 * Every UDP FINS message opens with a fixed 10-byte FINS header — ICF (Information Control Field), a
 * reserved octet, GCT (Gateway Count), the destination address triple DNA/DA1/DA2 (network / node /
 * unit), the source address triple SNA/SA1/SA2, and SID (Service ID) — followed by a 2-byte command
 * code (MRC/SRC, big-endian: 0x0101 Memory Area Read, 0x0102 Memory Area Write, 0x0501 Controller Status
 * Read, …) and the command-specific parameter/data area.
 *
 * The parameter/data area layout is command-dependent (and for responses carries a 2-byte end code and
 * variable data), cross-message state that this single-message codec does not sub-decode; it is kept
 * verbatim as `body` hex (byte-perfect), bounded by the captured UDP payload. There is no length field
 * in the FINS header — a single UDP datagram carries exactly one FINS message — so the body runs to the
 * end of the payload and a well-formed message round-trips byte-for-byte. The command is stored as a
 * plain integer (no enum) so any on-wire MRC/SRC value decodes and re-encodes without rejection.
 */
export class OmronFINS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (OmronFINS.#schemaCache ??= OmronFINS.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'FINS cmd=${command} ${sna}.${sa1}.${sa2}->${dna}.${da1}.${da2}',
            properties: {
                //ICF — Information Control Field: bit0 response-required flag, bit6 command/response,
                //bit7 gateway; kept as a whole octet so any legal value round-trips.
                icf: this.fieldUInt('icf', 0, 1, 'Information Control Field'),
                //Reserved octet — kept verbatim.
                rsv: this.fieldUInt('rsv', 1, 1, 'Reserved'),
                //Gateway Count — how many gateways the message may still traverse.
                gct: this.fieldUInt('gct', 2, 1, 'Gateway Count'),
                dna: this.fieldUInt('dna', 3, 1, 'Destination Network Address'),
                da1: this.fieldUInt('da1', 4, 1, 'Destination Node Address'),
                da2: this.fieldUInt('da2', 5, 1, 'Destination Unit Address'),
                sna: this.fieldUInt('sna', 6, 1, 'Source Network Address'),
                sa1: this.fieldUInt('sa1', 7, 1, 'Source Node Address'),
                sa2: this.fieldUInt('sa2', 8, 1, 'Source Unit Address'),
                sid: this.fieldUInt('sid', 9, 1, 'Service ID'),
                //Command code MRC/SRC, big-endian (0x0101 Memory Area Read, 0x0102 Write, 0x0501
                //Controller Status Read, …). Plain integer — any on-wire value decodes/re-encodes.
                command: this.fieldUInt('command', 10, 2, 'Command Code'),
                //Command-specific parameter/data area, kept verbatim. Bounded by the captured UDP
                //payload (a single datagram = one FINS message), so the whole remainder is consumed.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: OmronFINS): void {
                        const remaining: number = this.packet.length - this.startPos
                        this.instance.body.setValue(remaining > 12 ? BufferToHex(this.readBytes(12, remaining - 12)) : '')
                    },
                    encode: function (this: OmronFINS): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(12, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'fins'

    public readonly name: string = 'OMRON FINS'

    public readonly nickname: string = 'FINS'

    public readonly matchKeys: string[] = ['udpport:9600']

    public match(): boolean {
        //UDP FINS rides on port 9600. The FINS header carries no strong content magic, so the
        //well-known port is the signature: require the full 10-byte header + 2-byte command (12 bytes)
        //to be present so a too-short datagram falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        return this.packet.length - this.startPos >= 12
    }

    //A leaf header — the parameter/data area requires per-command, cross-message parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
