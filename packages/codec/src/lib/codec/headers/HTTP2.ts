import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * HTTP/2 over cleartext TCP — "h2c" (RFC 7540), well-known ports 80 / 8080. (HTTP/2 over TLS is
 * negotiated by the ALPN identifier "h2" and lives INSIDE the TLS record layer, so it is not decoded
 * here.) A client opens an h2c connection with the 24-byte connection preface
 * `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` (RFC 7540 §3.5) — an extremely distinctive signature — immediately
 * followed by frames. Every frame is a 9-byte header: Length (24-bit, the payload octet count), Type
 * (1 = HEADERS, 4 = SETTINGS, 6 = PING, 8 = WINDOW_UPDATE, 0 = DATA, …), Flags (1 byte), a 1-bit
 * Reserved and a 31-bit Stream Identifier (RFC 7540 §4.1), then Length bytes of payload.
 *
 * This is a MINIMAL first-slice codec: it matches only the connection-preface packet (the preface is
 * the sole reliable content signature — a bare 9-byte frame header is not distinctive enough to claim
 * arbitrary TCP traffic) and structures the preface plus exactly the FIRST frame that follows it. The
 * frame's payload is kept verbatim as `payload` hex (its internal structure — HPACK header blocks,
 * per-type SETTINGS/PING/WINDOW_UPDATE fields — is per-type, and HPACK is cross-frame connection state,
 * out of scope for a single-packet slice). The frame is bounded by its Length, so any further pipelined
 * frames in the same segment are left to the codec's recursion / RawData (they carry no preface, so
 * this header does not re-match them). Length is honored when supplied else derived from the payload;
 * Reserved and Stream Identifier are preserved verbatim. A well-formed preface packet round-trips
 * byte-for-byte.
 */
export class HTTP2 extends BaseHeader {

    /** The 24-byte HTTP/2 connection preface (RFC 7540 §3.5): "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n". */
    static readonly #PREFACE_HEX: string = '505249202a20485454502f322e300d0a0d0a534d0d0a0d0a'

    /** Preface (24) + fixed 9-byte frame header — the bytes this header always structures and re-emits. */
    static readonly #MIN_LENGTH: number = 33

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (HTTP2.#schemaCache ??= HTTP2.#buildSchema())
    }

    /** Bytes available to this header within the current TCP segment. */
    #available(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'HTTP2 type=${type} stream=${streamId} len=${length}',
            properties: {
                //The 24-byte connection preface, kept verbatim. match() requires it, so it is always
                //present on decode; the default lets a crafted frame re-emit the standard preface.
                preface: {
                    type: 'string',
                    label: 'Connection Preface',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: HTTP2): void {
                        this.instance.preface.setValue(BufferToHex(this.readBytes(0, 24)))
                    },
                    encode: function (this: HTTP2): void {
                        this.writeBytes(0, HexToBuffer(this.instance.preface.getValue(HTTP2.#PREFACE_HEX)))
                    }
                },
                //Frame payload Length: a 24-bit big-endian octet count (RFC 7540 §4.1). There is no
                //uint24 helper, so it is read/written byte-by-byte. Honored when supplied (a crafted
                //frame may lie); else derived from the payload byte length.
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 16777215,
                    decode: function (this: HTTP2): void {
                        const b: Buffer = this.readBytes(24, 3)
                        this.instance.length.setValue((b[0] << 16) | (b[1] << 8) | b[2])
                    },
                    encode: function (this: HTTP2): void {
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.payload.getValue('')).length
                        if (value > 16777215) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 16777215')
                            value = 16777215
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(24, Buffer.from([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]))
                    }
                },
                //Frame Type (RFC 7540 §6): 0 DATA, 1 HEADERS, 4 SETTINGS, 6 PING, 8 WINDOW_UPDATE, … Kept
                //as a plain uint8 (no hard enum) so any unknown/experimental type still round-trips.
                type: this.fieldUInt('type', 27, 1, 'Type'),
                //Frame Flags (RFC 7540 §4.1): a type-specific bit set (END_STREAM, END_HEADERS, ACK, …).
                flags: this.fieldUInt('flags', 28, 1, 'Flags'),
                //Reserved 1-bit field (RFC 7540 §4.1): the high bit of the 4-byte Stream-Identifier word.
                //"MUST remain unset when sending"; preserved verbatim so a set bit still round-trips.
                reserved: {
                    type: 'integer',
                    label: 'Reserved',
                    minimum: 0,
                    maximum: 1,
                    decode: function (this: HTTP2): void {
                        this.instance.reserved.setValue(this.readBits(29, 4, 0, 1))
                    },
                    encode: function (this: HTTP2): void {
                        const node: any = this.instance.reserved
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 1) value = 1
                        if (value < 0) value = 0
                        node.setValue(value)
                        this.writeBits(29, 4, 0, 1, value)
                    }
                },
                //Stream Identifier (RFC 7540 §4.1): the low 31 bits of the same word. 0 = connection
                //control (SETTINGS/PING/WINDOW_UPDATE); odd = client-initiated, even = server-initiated.
                streamId: {
                    type: 'integer',
                    label: 'Stream Identifier',
                    minimum: 0,
                    maximum: 2147483647,
                    decode: function (this: HTTP2): void {
                        this.instance.streamId.setValue(this.readBits(29, 4, 1, 31))
                    },
                    encode: function (this: HTTP2): void {
                        const node: any = this.instance.streamId
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 2147483647) {
                            this.recordError(node.getPath(), 'Maximum value is 2147483647')
                            value = 2147483647
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBits(29, 4, 1, 31, value)
                    }
                },
                //The first frame's payload after the 9-byte frame header (offset 33 = preface 24 + header
                //9), kept verbatim. Bounded by the frame Length AND the captured bytes, so any pipelined
                //trailing frame is left to the codec's recursion / RawData.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: HTTP2): void {
                        const available: number = this.#available()
                        const length: number = this.instance.length.getValue(0)
                        let end: number = 33 + length
                        if (end > available) end = available
                        this.instance.payload.setValue(end > 33 ? BufferToHex(this.readBytes(33, end - 33)) : '')
                    },
                    encode: function (this: HTTP2): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(33, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'http2'

    public readonly name: string = 'Hypertext Transfer Protocol 2'

    public readonly nickname: string = 'HTTP2'

    //Well-known h2c ports for O(1) bucket dispatch, plus heuristicFallback so a preface on any other
    //port is still recognized via match(). The 24-byte connection preface is a strong, unique content
    //signature (STUN/HTTP use the same dual pattern), so this cannot claim arbitrary TCP traffic.
    public readonly matchKeys: string[] = ['tcpport:80', 'tcpport:8080']

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        //h2c rides on TCP. Recognize ONLY the connection-preface packet: the exact 24-byte preface plus
        //enough bytes for the fixed 9-byte frame header this codec always structures and re-emits (so a
        //preface-only segment is not claimed and left byte-imperfect). A bare mid-stream frame carries
        //no preface and is intentionally not matched (it falls through to raw).
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.#available() < HTTP2.#MIN_LENGTH) return false
        return BufferToHex(this.readBytes(0, 24, true)) === HTTP2.#PREFACE_HEX
    }

    //A leaf header — the frame payload (HPACK header blocks, per-type fields) needs cross-frame
    //connection state and per-type parsing, out of scope for this single-packet slice.
    public readonly demuxProducers: DemuxProducer[] = []

}
