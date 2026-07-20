import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * The valid NetBIOS Session Service packet types (RFC 1002 §4.3.1): 0x00 Session Message,
 * 0x81 Session Request, 0x82 Positive Session Response, 0x83 Negative Session Response,
 * 0x84 Retarget Response, 0x85 Session Keep Alive. Used as the match() signature on port 139.
 */
const NBSS_TYPES: ReadonlySet<number> = new Set([0x00, 0x81, 0x82, 0x83, 0x84, 0x85])

/**
 * NBSS — NetBIOS Session Service (RFC 1002), TCP port 139. Every session-service PDU begins with a fixed
 * 4-byte header:
 *
 *      0               1               2               3
 *     +-------------- -+---------------+-------------------------------+
 *     |     TYPE      |    FLAGS    |E|            LENGTH              |
 *     +---------------+---------------+-------------------------------+
 *
 * TYPE (1 byte) names the PDU (0x00 Session Message, 0x81 Session Request, 0x82/0x83 Positive/Negative
 * Session Response, 0x84 Retarget, 0x85 Keep Alive). FLAGS (1 byte) is seven reserved bits plus an
 * Extension bit E in its least-significant position — E is bit 16 (the high-order bit) of a 17-bit LENGTH
 * whose low 16 bits are the following 2-byte field. So the trailer byte count is
 * ((FLAGS & 0x01) << 16) | LENGTH16, and the payload (an SMB message for a Session Message, the encoded
 * Called/Calling NetBIOS names for a Session Request, empty for Keep Alive / responses) follows the header.
 *
 * Byte-perfect strategy: structure type + flags (both verbatim, so the reserved bits and the E bit
 * round-trip exactly) + the 16-bit length, and keep the payload verbatim as `payload` hex bounded by the
 * 17-bit length. The length is honored when supplied (a crafted PDU may lie) else derived from the actual
 * payload byte count; the payload is bounded by the length so a second pipelined PDU or Ethernet padding is
 * left to the codec's recursion / RawData. Sub-decoding the SMB payload / the NetBIOS names is a later
 * enrichment. A well-formed PDU round-trips byte-for-byte.
 */
export class NBSS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (NBSS.#schemaCache ??= NBSS.#buildSchema())
    }

    /**
     * The 17-bit trailer byte count = the Extension bit E (FLAGS bit 0) as bit 16, plus the 16-bit LENGTH.
     * Read dry-run so it can be used to bound the payload without disturbing the decoded header length.
     */
    #declaredLength(): number {
        const flags: number = this.readBytes(1, 1, true)[0]
        const low16: number = BufferToUInt16(this.readBytes(2, 2, true))
        return ((flags & 0x01) * 0x10000) + low16
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'NBSS type=${type} len=${length}',
            properties: {
                //0x00 Session Message, 0x81 Session Request, 0x82/0x83 Positive/Negative Response,
                //0x84 Retarget, 0x85 Keep Alive. Kept verbatim.
                type: this.fieldUInt('type', 0, 1, 'Type'),
                //Seven reserved bits + the Extension bit E in the LSB (bit 16 of the 17-bit length). Kept
                //verbatim so the reserved bits and E round-trip; the payload boundary reads E from here.
                flags: this.fieldUInt('flags', 1, 1, 'Flags'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: NBSS): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: NBSS): void {
                        //The low 16 bits of the trailer byte count. Honored when supplied (a crafted PDU may
                        //lie); else derived from the actual payload length (its low 16 bits — the E bit lives
                        //in the verbatim FLAGS byte and is not synthesized here).
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.payload.getValue('')).length % 0x10000
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(2, UInt16ToBuffer(value))
                    }
                },
                //The PDU payload after the 4-byte header, kept verbatim. Bounded by the 17-bit declared
                //length and the captured bytes, so trailing / pipelined PDUs and Ethernet padding are left
                //to the codec's recursion / RawData (never read to the buffer end).
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: NBSS): void {
                        const remaining: number = this.packet.length - this.startPos - 4
                        let length: number = this.#declaredLength()
                        if (length > remaining) length = remaining
                        this.instance.payload.setValue(length > 0 ? BufferToHex(this.readBytes(4, length)) : '')
                    },
                    encode: function (this: NBSS): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(4, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'nbss'

    public readonly name: string = 'NetBIOS Session Service'

    public readonly nickname: string = 'NBSS'

    public readonly matchKeys: string[] = ['tcpport:139']

    public match(): boolean {
        //NBSS rides on TCP port 139 (selected via the tcpport:139 bucket). This stays a port-bucket
        //protocol: matchKeys only, NO heuristicFallback — a single valid type byte is too weak a signature
        //to claim NBSS off port 139, and non-NBSS traffic on 139 must fall through to raw. Require the full
        //4-byte header within the captured bytes and a recognized packet type.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 4) return false
        const type: number = this.readBytes(0, 1, true)[0]
        return NBSS_TYPES.has(type)
    }

    //A leaf header — the SMB payload / the encoded NetBIOS names are kept verbatim for now.
    public readonly demuxProducers: DemuxProducer[] = []

}
