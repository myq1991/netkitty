import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * CODESYS V3 (3S-Smart Software Solutions runtime) communication, TCP port 2455. CODESYS wraps its
 * multi-layer message stack (an L3 datagram/router layer, an L4 channel layer and an L7 service layer)
 * inside an outer "block driver" frame: a fixed 8-byte header — a 4-byte magic (`00 01 17 e8`) and a
 * LITTLE-ENDIAN 32-bit Length — followed by the block-driver payload.
 *
 * ⚠️ No authoritative public specification of the CODESYS wire format exists. The block-driver framing
 * used here (magic + little-endian length) is inferred from the community Wireshark dissector
 * `fridgebuyer/codesys3-dissector` (and the ICS-pcap CODESYS notes), not from a vendor spec — so this
 * codec surfaces only the two determinable header fields and keeps the entire block-driver payload
 * (the L3/L4/L7 stack, which needs cross-message / session context) verbatim as `payload` hex
 * (byte-perfect). The Length is auto-computed from the payload on encode when not supplied, else honored
 * verbatim (a crafted frame may carry any Length); the payload is bounded by the Length so a second
 * pipelined block-driver frame or trailing bytes are left to the codec's recursion / RawData. A
 * well-formed frame round-trips byte-for-byte.
 *
 * Like the other multi-byte CODESYS/CIP-style protocols, the Length is little-endian; there is no
 * little-endian helper in this codebase, so it is read/written byte-by-byte in its closures.
 */
export class Codesys extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Codesys.#schemaCache ??= Codesys.#buildSchema())
    }

    /** The 4-byte block-driver magic that prefixes every frame, as a wire-order byte sequence. */
    static readonly #MAGIC: string = '000117e8'

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'CODESYS len=${length}',
            properties: {
                //The 4-byte block-driver magic (00 01 17 e8). Kept verbatim (not enum-constrained) so any
                //observed frame round-trips even if a variant carries a different signature.
                magic: this.fieldHex('magic', 0, 4, 'Block Driver Magic'),
                //Block-driver payload byte count that follows the 8-byte header. LITTLE-ENDIAN 32-bit.
                //Honored when supplied (a crafted frame may lie); else derived from the payload bytes.
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: Codesys): void {
                        const b: Buffer = this.readBytes(4, 4)
                        //`|` yields a signed int32, so `>>> 0` over the WHOLE expression keeps it unsigned.
                        this.instance.length.setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
                    },
                    encode: function (this: Codesys): void {
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.payload.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(4, Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff]))
                    }
                },
                //The block-driver payload (the CODESYS L3/L4/L7 stack), kept verbatim. Bounded by the
                //Length field (payload ends at offset 8 + Length) when the Length is sane and the captured
                //bytes, so a trailing / pipelined frame is left to the codec's recursion / RawData.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: Codesys): void {
                        const available: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        //Honor the Length to bound the payload when it fits within the captured bytes;
                        //otherwise (0, or a lying/oversized Length) consume the rest so nothing is lost.
                        let end: number = 8 + length
                        if (length <= 0 || end > available) end = available
                        this.instance.payload.setValue(end > 8 ? BufferToHex(this.readBytes(8, end - 8)) : '')
                    },
                    encode: function (this: Codesys): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(8, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'codesys'

    public readonly name: string = 'CODESYS V3'

    public readonly nickname: string = 'CODESYS'

    public readonly matchKeys: string[] = ['tcpport:2455']

    public match(): boolean {
        //CODESYS V3 rides on TCP port 2455 (an observed runtime/gateway port). Require the full 8-byte
        //block-driver header and the 4-byte magic signature (00 01 17 e8) so non-CODESYS 2455 traffic
        //falls through to raw. The magic is a strong 32-bit content signature, but selection stays
        //port-bucketed (matchKeys) like the other length-bounded TCP-payload codecs.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 8) return false
        return BufferToHex(this.readBytes(0, 4, true)) === Codesys.#MAGIC
    }

    //A leaf header — the block-driver payload (L3/L4/L7) requires cross-message / session parsing that
    //has no authoritative public spec, so it is kept as hex rather than demuxed further.
    public readonly demuxProducers: DemuxProducer[] = []

}
