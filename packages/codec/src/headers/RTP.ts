import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt16} from '../helper/BufferToNumber'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * RTP — Real-time Transport Protocol (RFC 3550), carried over UDP on application-negotiated (SDP)
 * dynamic ports. The 12-byte fixed header is: byte 0 = Version(2 bits, always 2) + Padding(P) +
 * Extension(X) + CSRC Count(CC, 4 bits); byte 1 = Marker(M) + Payload Type(PT, 7 bits); then a 16-bit
 * Sequence Number, a 32-bit Timestamp and a 32-bit SSRC. It is followed by CC × 4-byte CSRC identifiers,
 * an optional header extension (present when X=1: a 16-bit profile id + a 16-bit length in 32-bit words +
 * length×4 bytes of data), and the media payload.
 *
 * ⚠️ RTP has no in-band magic — its only signature is the 2-bit Version field (==2), far too weak to
 * heuristically claim arbitrary UDP traffic (that would swallow every UDP flow). So this codec is
 * port-bucketed ONLY (the common RTP/AVP default even ports 5004/5006/5008) with NO heuristicFallback,
 * and its match() still requires Version==2 and the full 12-byte header. Real deployments negotiate the
 * port via SDP, so an editor should offer an explicit decode-as for other ports rather than any guess.
 *
 * The CSRC list, optional extension and payload are parsed generically (identifiers/extension data kept
 * verbatim as hex, payload bounded by the UDP datagram so a retained FCS/padding is not absorbed). The
 * CSRC Count is honored-else-derived from the CSRC list; the extension length is honored-else-derived
 * from the extension data byte length; the payload-type-specific media bytes are a leaf (not sub-decoded).
 * A well-formed packet round-trips byte-for-byte.
 */
export class RTP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (RTP.#schemaCache ??= RTP.#buildSchema())
    }

    /**
     * The RTP length (fixed header + CSRC + extension + payload) bounded by the enclosing UDP datagram,
     * so a lying CC/extension length near the end does not read into a retained FCS/padding. Bounds the
     * field reads and the match gate.
     */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /** A fixed-width big-endian unsigned bit field within one octet at `byteOffset` (bitOffset 0 = MSB). */
    static #uintBits(name: string, byteOffset: number, bitOffset: number, bitLength: number, label: string): ProtocolFieldJSONSchema {
        const maximum: number = (2 ** bitLength) - 1
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: maximum,
            decode: function (this: RTP): void {
                (this.instance as any)[name].setValue(this.readBits(byteOffset, 1, bitOffset, bitLength))
            },
            encode: function (this: RTP): void {
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > maximum) {
                    this.recordError(node.getPath(), `Maximum value is ${maximum}`)
                    value = maximum
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBits(byteOffset, 1, bitOffset, bitLength, value)
            }
        }
    }

    /** A single flag bit within one octet at `byteOffset` (bitOffset 0 = MSB). */
    static #flagBit(name: string, byteOffset: number, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'boolean',
            label: label,
            decode: function (this: RTP): void {
                (this.instance as any)[name].setValue(!!this.readBits(byteOffset, 1, bitOffset, 1))
            },
            encode: function (this: RTP): void {
                const value: boolean = !!(this.instance as any)[name].getValue()
                ;(this.instance as any)[name].setValue(value)
                this.writeBits(byteOffset, 1, bitOffset, 1, value ? 1 : 0)
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'RTP pt=${payloadType} seq=${sequenceNumber} ssrc=${ssrc}',
            properties: {
                //Byte 0 (MSB first): Version(0-1) Padding(2) Extension(3) CSRC Count(4-7).
                version: this.#uintBits('version', 0, 0, 2, 'Version'),
                padding: this.#flagBit('padding', 0, 2, 'Padding'),
                extension: this.#flagBit('extension', 0, 3, 'Extension'),
                //CSRC Count: the number of 4-byte CSRC identifiers. Honored when supplied (a crafted
                //packet may lie), else derived from the CSRC list length; written into byte 0 bits 4-7.
                csrcCount: {
                    type: 'integer',
                    label: 'CSRC Count',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: RTP): void {
                        this.instance.csrcCount.setValue(this.readBits(0, 1, 4, 4))
                    },
                    encode: function (this: RTP): void {
                        const provided: number | undefined = this.instance.csrcCount.getValue()
                        const csrc: unknown = this.instance.csrc.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : (Array.isArray(csrc) ? csrc.length : 0)
                        if (value > 15) {
                            this.recordError(this.instance.csrcCount.getPath(), 'Maximum value is 15')
                            value = 15
                        }
                        if (value < 0) value = 0
                        this.instance.csrcCount.setValue(value)
                        this.writeBits(0, 1, 4, 4, value)
                    }
                },
                //Byte 1 (MSB first): Marker(0) Payload Type(1-7).
                marker: this.#flagBit('marker', 1, 0, 'Marker'),
                payloadType: this.#uintBits('payloadType', 1, 1, 7, 'Payload Type'),
                sequenceNumber: this.fieldUInt('sequenceNumber', 2, 2, 'Sequence Number'),
                timestamp: this.fieldUInt('timestamp', 4, 4, 'Timestamp'),
                ssrc: this.fieldUInt('ssrc', 8, 4, 'SSRC'),
                //CC × 4-byte contributing-source identifiers, kept verbatim as hex. Populated by the
                //master `body` field (offsets depend on the CC count decoded above).
                csrc: {
                    type: 'array',
                    label: 'CSRC List',
                    items: {
                        type: 'string',
                        label: 'CSRC',
                        contentEncoding: StringContentEncodingEnum.HEX
                    }
                },
                //Optional header extension (RFC 3550 §5.3.1), present only when the Extension (X) flag is
                //set: a 16-bit profile id, a 16-bit length in 32-bit words, then length×4 bytes of data.
                //Populated by the master `body` field.
                extensionHeader: {
                    type: 'object',
                    label: 'Header Extension',
                    properties: {
                        profile: {type: 'integer', label: 'Profile', minimum: 0, maximum: 65535},
                        length: {type: 'integer', label: 'Length (32-bit words)', minimum: 0, maximum: 65535},
                        data: {type: 'string', label: 'Data', contentEncoding: StringContentEncodingEnum.HEX}
                    }
                },
                //The media payload, kept verbatim as hex, bounded by the UDP datagram. Payload-type
                //(codec) specific de-structuring is a leaf — not sub-decoded here.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX
                },
                //Master field: the CSRC list, optional extension and payload have flag/count-dependent
                //offsets, so they are parsed/emitted together here (runs after the fixed fields — property
                //order). Hidden: it carries no value of its own, only drives the variable-length tail.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    hidden: true,
                    decode: function (this: RTP): void {
                        const available: number = this.#available()
                        //CSRC count clamped to the spec's 0-15 AND to the bytes actually present, so a
                        //lying count cannot spawn phantom identifiers past the datagram end.
                        let count: number = this.instance.csrcCount.getValue(0)
                        if (count < 0) count = 0
                        if (count > 15) count = 15
                        if (12 + count * 4 > available) count = Math.floor((available - 12) / 4)
                        if (count < 0) count = 0
                        let offset: number = 12
                        const csrc: string[] = []
                        for (let i: number = 0; i < count; i++) {
                            csrc.push(BufferToHex(this.readBytes(offset, 4)))
                            offset += 4
                        }
                        this.instance.csrc.setValue(csrc)
                        const hasExtension: boolean = !!this.instance.extension.getValue()
                        if (hasExtension && offset + 4 <= available) {
                            const profile: number = BufferToUInt16(this.readBytes(offset, 2))
                            const words: number = BufferToUInt16(this.readBytes(offset + 2, 2))
                            offset += 4
                            let dataBytes: number = words * 4
                            if (offset + dataBytes > available) dataBytes = available - offset
                            if (dataBytes < 0) dataBytes = 0
                            const data: string = dataBytes > 0 ? BufferToHex(this.readBytes(offset, dataBytes)) : ''
                            offset += dataBytes
                            this.instance.extensionHeader.profile.setValue(profile)
                            this.instance.extensionHeader.length.setValue(words)
                            this.instance.extensionHeader.data.setValue(data)
                        }
                        const payloadBytes: number = available - offset > 0 ? available - offset : 0
                        this.instance.payload.setValue(payloadBytes > 0 ? BufferToHex(this.readBytes(offset, payloadBytes)) : '')
                    },
                    encode: function (this: RTP): void {
                        let offset: number = 12
                        const csrc: unknown = this.instance.csrc.getValue()
                        if (Array.isArray(csrc)) {
                            csrc.forEach((entry: unknown): void => {
                                //Normalize each identifier to exactly 4 bytes so the tail stays aligned
                                //(a decoded entry is 8 hex chars → copied whole; a crafted one is padded/
                                //truncated).
                                const source: Buffer = HexToBuffer(typeof entry === 'string' && entry ? entry : '00000000')
                                const four: Buffer = Buffer.alloc(4)
                                source.copy(four, 0, 0, 4)
                                this.writeBytes(offset, four)
                                offset += 4
                            })
                        }
                        //Emit the extension only when the X flag is set AND an extension header was
                        //actually captured on decode. A malformed packet with X=1 but too few trailing
                        //bytes decodes without an extensionHeader (the decode gates on availability); if
                        //encode emitted one solely from the X bit it would synthesize 4 zero bytes the
                        //wire never had, breaking byte-perfect. Honoring the captured extension keeps them
                        //symmetric.
                        const extHeader: unknown = this.instance.extensionHeader.getValue()
                        const hasExtension: boolean = !!this.instance.extension.getValue() && extHeader !== undefined && extHeader !== null
                        if (hasExtension) {
                            let profile: number = this.instance.extensionHeader.profile.getValue(0)
                            if (profile > 65535) profile = 65535
                            if (profile < 0) profile = 0
                            const data: string = this.instance.extensionHeader.data.getValue('')
                            const dataBuffer: Buffer = HexToBuffer(data)
                            //Length honored when supplied (a crafted packet may lie), else derived from
                            //the data byte length (in 32-bit words).
                            const providedLength: number | undefined = this.instance.extensionHeader.length.getValue()
                            let words: number = (providedLength !== undefined && providedLength !== null)
                                ? providedLength
                                : Math.ceil(dataBuffer.length / 4)
                            if (words > 65535) words = 65535
                            if (words < 0) words = 0
                            this.instance.extensionHeader.profile.setValue(profile)
                            this.instance.extensionHeader.length.setValue(words)
                            this.writeBytes(offset, UInt16ToBuffer(profile))
                            this.writeBytes(offset + 2, UInt16ToBuffer(words))
                            offset += 4
                            if (dataBuffer.length) {
                                this.writeBytes(offset, dataBuffer)
                                offset += dataBuffer.length
                            }
                        }
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(offset, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'rtp'

    public readonly name: string = 'Real-time Transport Protocol'

    public readonly nickname: string = 'RTP'

    //RTP/AVP common default even ports only. RTP has no reliable content magic (Version==2 is a 2-bit
    //signature), so it is NEVER placed in the heuristic fallback list — matching arbitrary UDP traffic
    //would swallow every UDP flow. Real ports are negotiated by SDP; an editor should decode-as for them.
    public readonly matchKeys: string[] = ['udpport:5004', 'udpport:5006', 'udpport:5008']

    public match(): boolean {
        //RTP rides on UDP (one of the default RTP/AVP ports). Require the full 12-byte fixed header within
        //the datagram and the Version==2 signature (bits 7:6 of byte 0) so a non-RTP datagram on the port
        //falls through to raw rather than claiming an un-decodable layer.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.#available() < 12) return false
        return this.readBits(0, 1, 0, 2) === 2
    }

    //A leaf header — payload-type (codec) specific media de-structuring is deferred to a later slice.
    public readonly demuxProducers: DemuxProducer[] = []

}
