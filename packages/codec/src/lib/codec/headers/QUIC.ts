import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt8ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * QUIC — the UDP-based multiplexed and secure transport (RFC 9000), the substrate under HTTP/3. Every
 * QUIC packet begins with a first byte whose most-significant bit is the Header Form: 1 = Long Header
 * (used during connection setup — Initial / 0-RTT / Handshake / Retry / Version Negotiation), 0 = Short
 * Header (1-RTT, used once the connection is established). This header structures the LONG header only:
 *
 *   first byte  = Header Form(1) | Fixed Bit(1) | Long Packet Type(2) | type-specific(4)
 *   Version(4) | DCID Len(1) | DCID(DCID Len) | SCID Len(1) | SCID(SCID Len) | ...rest
 *
 * Everything after the Source Connection ID (token / length / packet number / frames) is protected by
 * QUIC header protection + AEAD encryption, so it is kept verbatim as an opaque `payload` hex (bounded
 * by the UDP payload) — this is a best-effort structural slice, not a decryptor. The one exception is
 * Version Negotiation (Version == 0, RFC 9000 §17.2.1): its body is an unencrypted list of 4-byte
 * Supported Versions, decoded into `supportedVersions`.
 *
 * The Short Header (MSB clear) is deliberately NOT recognized by the content heuristic — its first byte
 * is an almost signature-free value, so heuristic matching would over-claim ordinary UDP traffic; it is
 * left to later enrichment / RawData. The connection-ID length fields are honored when supplied else
 * derived from the ID bytes; the type-specific bits and all opaque bytes round-trip byte-for-byte.
 */
export class QUIC extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (QUIC.#schemaCache ??= QUIC.#buildSchema())
    }

    /**
     * Bytes available to this QUIC packet, bounded by the enclosing UDP payload (udp.length - 8) so a
     * lying connection-ID length near the end of the datagram cannot read into trailing bytes, and so the
     * opaque payload stops at the datagram boundary rather than swallowing the whole captured buffer.
     */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpPayload: number = prev.instance.length.getValue(0) - 8
            if (udpPayload >= 0 && udpPayload < available) available = udpPayload
        }
        return available < 0 ? 0 : available
    }

    /** Absolute (header-relative) offset of the SCID Length octet = 6 + DCID Len. */
    #scidLengthOffset(): number {
        return 6 + this.instance.dcidLength.getValue(0)
    }

    /** Absolute (header-relative) offset of the bytes following the SCID = 7 + DCID Len + SCID Len. */
    #tailOffset(): number {
        return 7 + this.instance.dcidLength.getValue(0) + this.instance.scidLength.getValue(0)
    }

    /** A single flag bit within the first byte (bit 0 = MSB). */
    static #flagBit(name: string, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'boolean',
            label: label,
            decode: function (this: QUIC): void {
                (this.instance.firstByte as any)[name].setValue(!!this.readBits(0, 1, bitOffset, 1))
            },
            encode: function (this: QUIC): void {
                const value: boolean = !!(this.instance.firstByte as any)[name].getValue()
                ;(this.instance.firstByte as any)[name].setValue(value)
                this.writeBits(0, 1, bitOffset, 1, value ? 1 : 0)
            }
        }
    }

    /** An unsigned integer packed into `bitLength` bits of the first byte at `bitOffset` (MSB-first). */
    static #uintBits(name: string, bitOffset: number, bitLength: number, label: string): ProtocolFieldJSONSchema {
        const maximum: number = (1 << bitLength) - 1
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: maximum,
            decode: function (this: QUIC): void {
                (this.instance.firstByte as any)[name].setValue(this.readBits(0, 1, bitOffset, bitLength))
            },
            encode: function (this: QUIC): void {
                const node: any = (this.instance.firstByte as any)[name]
                let value: number = node.getValue(0)
                if (value > maximum) value = maximum
                if (value < 0) value = 0
                node.setValue(value)
                this.writeBits(0, 1, bitOffset, bitLength, value)
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'QUIC v=${version} type=${firstByte.longPacketType}',
            properties: {
                //First byte: Header Form(bit0) | Fixed Bit(bit1) | Long Packet Type(bits2-3) |
                //type-specific(bits4-7). For Initial/0-RTT/Handshake the low 4 bits are Reserved(2) +
                //Packet Number Length(2) but they are masked by header protection on the wire, so they are
                //kept verbatim as a single opaque 4-bit field (Retry has no such split).
                firstByte: {
                    type: 'object',
                    label: 'First Byte',
                    properties: {
                        headerForm: this.#flagBit('headerForm', 0, 'Header Form (1=Long)'),
                        fixedBit: this.#flagBit('fixedBit', 1, 'Fixed Bit'),
                        longPacketType: this.#uintBits('longPacketType', 2, 2, 'Long Packet Type'),
                        typeSpecificBits: this.#uintBits('typeSpecificBits', 4, 4, 'Type-Specific Bits')
                    }
                },
                //Version — 0x00000001 = QUIC v1 (RFC 9000), 0x6b3343cf = v2 (RFC 9369), 0xff0000xx = IETF
                //drafts, 0x00000000 = Version Negotiation. Kept as a lower-case hex string so any value
                //round-trips verbatim and the field is unbounded (the match gate restricts real selection).
                version: this.fieldHex('version', 1, 4, 'Version'),
                //Destination Connection ID length (0..20 per RFC 9000, but any 0..255 round-trips). Honored
                //when supplied, else derived from the DCID bytes.
                dcidLength: {
                    type: 'integer',
                    label: 'DCID Length',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: QUIC): void {
                        this.instance.dcidLength.setValue(BufferToUInt8(this.readBytes(5, 1)))
                    },
                    encode: function (this: QUIC): void {
                        const provided: number | undefined = this.instance.dcidLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.dcid.getValue('')).length
                        if (value > 255) value = 255
                        if (value < 0) value = 0
                        this.instance.dcidLength.setValue(value)
                        this.writeBytes(5, UInt8ToBuffer(value))
                    }
                },
                //Destination Connection ID, kept verbatim. Bounded by DCID Len and the UDP payload.
                dcid: {
                    type: 'string',
                    label: 'Destination Connection ID',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: QUIC): void {
                        const dcidLength: number = this.instance.dcidLength.getValue(0)
                        this.instance.dcid.setValue(dcidLength > 0 ? BufferToHex(this.readBytes(6, dcidLength)) : '')
                    },
                    encode: function (this: QUIC): void {
                        const dcid: string = this.instance.dcid.getValue('')
                        if (dcid) this.writeBytes(6, HexToBuffer(dcid))
                    }
                },
                //Source Connection ID length. Offset is dynamic (after the DCID). Honored else derived.
                scidLength: {
                    type: 'integer',
                    label: 'SCID Length',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: QUIC): void {
                        this.instance.scidLength.setValue(BufferToUInt8(this.readBytes(this.#scidLengthOffset(), 1)))
                    },
                    encode: function (this: QUIC): void {
                        const provided: number | undefined = this.instance.scidLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.scid.getValue('')).length
                        if (value > 255) value = 255
                        if (value < 0) value = 0
                        this.instance.scidLength.setValue(value)
                        this.writeBytes(this.#scidLengthOffset(), UInt8ToBuffer(value))
                    }
                },
                //Source Connection ID, kept verbatim. Offset is dynamic (after the SCID Length octet).
                scid: {
                    type: 'string',
                    label: 'Source Connection ID',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: QUIC): void {
                        const scidLength: number = this.instance.scidLength.getValue(0)
                        const offset: number = this.#scidLengthOffset() + 1
                        this.instance.scid.setValue(scidLength > 0 ? BufferToHex(this.readBytes(offset, scidLength)) : '')
                    },
                    encode: function (this: QUIC): void {
                        const scid: string = this.instance.scid.getValue('')
                        if (scid) this.writeBytes(this.#scidLengthOffset() + 1, HexToBuffer(scid))
                    }
                },
                //Version Negotiation only (Version == 0): an unencrypted list of 4-byte Supported Versions
                //(RFC 9000 §17.2.1). Empty for every other packet type — mutually exclusive with `payload`.
                supportedVersions: {
                    type: 'array',
                    label: 'Supported Versions',
                    items: {
                        type: 'string',
                        label: 'Version',
                        contentEncoding: StringContentEncodingEnum.HEX
                    },
                    decode: function (this: QUIC): void {
                        const version: string = this.instance.version.getValue('')
                        if (version !== '00000000') {
                            this.instance.supportedVersions.setValue([])
                            return
                        }
                        const available: number = this.#available()
                        const versions: string[] = []
                        let offset: number = this.#tailOffset()
                        //Each Supported Version is exactly 4 bytes; stop at the datagram boundary. offset
                        //advances by 4 each turn so the loop always terminates.
                        while (offset + 4 <= available) {
                            versions.push(BufferToHex(this.readBytes(offset, 4)))
                            offset += 4
                        }
                        this.instance.supportedVersions.setValue(versions)
                    },
                    encode: function (this: QUIC): void {
                        const version: string = this.instance.version.getValue('')
                        if (version !== '00000000') return
                        const versions: string[] | undefined = this.instance.supportedVersions.getValue()
                        if (!versions) return
                        let offset: number = this.#tailOffset()
                        versions.forEach((version: string): void => {
                            //Each entry is sized to 4 bytes: extra dropped, short zero-padded — a
                            //Supported Version is a fixed 32-bit value.
                            this.writeBytes(offset, HexToBuffer(version ? version : '', 4))
                            offset += 4
                        })
                    }
                },
                //Everything after the SCID for a normal (non-VN) packet: token / length / packet number /
                //encrypted frames — kept verbatim (AEAD + header protection, not decryptable here).
                //Bounded by the UDP payload so a trailing datagram is left to the codec's recursion.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: QUIC): void {
                        const version: string = this.instance.version.getValue('')
                        if (version === '00000000') {
                            this.instance.payload.setValue('')
                            return
                        }
                        const available: number = this.#available()
                        const offset: number = this.#tailOffset()
                        this.instance.payload.setValue(offset < available ? BufferToHex(this.readBytes(offset, available - offset)) : '')
                    },
                    encode: function (this: QUIC): void {
                        const version: string = this.instance.version.getValue('')
                        if (version === '00000000') return
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(this.#tailOffset(), HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'quic'

    public readonly name: string = 'QUIC Transport'

    public readonly nickname: string = 'QUIC'

    //Bucketed on the common HTTP/3 port; heuristicFallback keeps it recognized on any other UDP port via
    //its long-header + known-version signature (QUIC is used on many ports).
    public readonly matchKeys: string[] = ['udpport:443']

    public readonly heuristicFallback: boolean = true

    /** True when the enclosing UDP source or destination port is the well-known QUIC port. */
    #onQuicPort(): boolean {
        const prev: any = this.prevCodecModule
        return prev.instance.srcport.getValue(0) === 443 || prev.instance.dstport.getValue(0) === 443
    }

    public match(): boolean {
        //QUIC rides UDP. Require the minimal long header (first byte + version + two length octets = 7
        //bytes) within the UDP payload, the Long Header form bit set, and — the strong part — a KNOWN
        //QUIC version. Short headers (MSB clear) and unknown versions are NOT heuristically claimed, so
        //ordinary UDP traffic falls through to raw. Version Negotiation (version 0) is a weak signature,
        //so it is only accepted on the well-known QUIC port bucket, never off-port via the heuristic.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.#available() < 7) return false
        if ((this.readBytes(0, 1, true)[0] & 0x80) === 0) return false
        const version: number = BufferToUInt32(this.readBytes(1, 4, true))
        if (version === 0x00000001) return true
        if (version === 0x6b3343cf) return true
        if ((version >>> 8) === 0xff0000) return true
        if (version === 0) return this.#onQuicPort()
        return false
    }

    //A leaf header — the payload is AEAD-encrypted and kept verbatim (no inner demux).
    public readonly demuxProducers: DemuxProducer[] = []

}
