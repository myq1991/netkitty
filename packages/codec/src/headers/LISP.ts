import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * LISP — Locator/ID Separation Protocol control plane (RFC 6830), UDP port 4342. Every LISP control
 * message begins with a 4-bit Type in the high nibble of the first octet (1 Map-Request, 2 Map-Reply,
 * 3 Map-Register, 4 Map-Notify, 8 Encapsulated Control Message), followed by a type-specific body of
 * flags, a Nonce, and AFI-tagged EID/RLOC records.
 *
 * The per-type body layout (Map-Request's Source-EID + ITR-RLOC list + record EID-prefixes,
 * Map-Reply/Register's locator records, the ECM's inner LISP-encapsulated control packet) is
 * self-delimited by AFI-tagged, count-driven sub-structures with no single length field, so this
 * minimal codec keeps the whole message verbatim as `message` hex (byte-perfect) and only surfaces the
 * Type nibble for display. The message is bounded by the UDP payload (it runs to the end of the
 * datagram); `message` is authoritative on encode (re-emitting every byte, including the Type nibble),
 * so a well-formed message round-trips byte-for-byte.
 *
 * The data plane (UDP 4341) whose payload is an inner IP packet is intentionally NOT handled here — it
 * would require the IP headers to match inside a LISP tunnel; left to a later enrichment.
 */
export class LISP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (LISP.#schemaCache ??= LISP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'LISP type=${type}',
            properties: {
                //Type: the high 4 bits of the first octet (RFC 6830 §5.3). 1 Map-Request, 2 Map-Reply,
                //3 Map-Register, 4 Map-Notify, 8 Encapsulated Control Message — kept as a plain 4-bit
                //integer (no enum: an unknown/out-of-spec type is still a legal decode and must
                //re-encode). Display only: `message` re-emits the whole octet, so this write is
                //overwritten by `message` when present; it lets a Type-only crafted message still emit.
                type: {
                    type: 'integer',
                    label: 'Type',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: LISP): void {
                        this.instance.type.setValue(this.readBits(0, 1, 0, 4))
                    },
                    encode: function (this: LISP): void {
                        const node: any = this.instance.type
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 15) {
                            this.recordError(node.getPath(), 'Maximum value is 15')
                            value = 15
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBits(0, 1, 0, 4, value)
                    }
                },
                //The whole control message kept verbatim (Type nibble included), bounded by the UDP
                //payload — a LISP control message has no length field and runs to the end of the
                //datagram. Authoritative on encode (re-emits every byte); UDP delivers exactly one
                //datagram so there is no trailing/pipelined data to leave for the codec's recursion.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: LISP): void {
                        const remaining: number = this.packet.length - this.startPos
                        this.instance.message.setValue(remaining > 0 ? BufferToHex(this.readBytes(0, remaining)) : '')
                    },
                    encode: function (this: LISP): void {
                        const message: string = this.instance.message.getValue('')
                        if (message) this.writeBytes(0, HexToBuffer(message))
                    }
                }
            }
        }
    }

    public readonly id: string = 'lisp'

    public readonly name: string = 'Locator/ID Separation Protocol'

    public readonly nickname: string = 'LISP'

    public readonly matchKeys: string[] = ['udpport:4342']

    public match(): boolean {
        //LISP control rides on UDP port 4342. The message carries no strong content magic (the leading
        //nibble is just a small type number), so the well-known port is the signature. Require a
        //minimum payload (Type octet + a partial fixed header) so a stray/empty UDP/4342 datagram
        //falls through to raw rather than being claimed as a 1-byte LISP message.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        return this.packet.length - this.startPos >= 4
    }

    //A leaf header — the per-type, AFI/count-driven body requires cross-record context to sub-decode.
    public readonly demuxProducers: DemuxProducer[] = []

}
