import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt8} from '../helper/BufferToNumber'
import {UInt8ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * FCoE — Fibre Channel over Ethernet (FC-BB-5 / T11), carried directly in an Ethernet II frame with
 * EtherType 0x8906 (an Ethernet child — no IP/UDP). An FCoE frame encapsulates a full native Fibre
 * Channel frame between a 14-byte FCoE header and a 4-byte FCoE trailer:
 *
 *   +--------------------------------------------------------------+
 *   | FCoE header (14 bytes): Version (high 4 bits of byte 0) +     |
 *   |   Reserved (low 4 bits of byte 0 + 12 bytes) + SOF (byte 13)  |
 *   +--------------------------------------------------------------+
 *   | Encapsulated FC frame: 24-byte FC header (R_CTL/D_ID/CS_CTL/  |
 *   |   S_ID/TYPE/F_CTL/SEQ_ID/DF_CTL/SEQ_CNT/OX_ID/RX_ID/Parameter)|
 *   |   + FC payload + 4-byte FC CRC                                |
 *   +--------------------------------------------------------------+
 *   | FCoE trailer (4 bytes): EOF (1 byte) + Reserved (3 bytes)     |
 *   +--------------------------------------------------------------+
 *
 * The Version nibble and the SOF/EOF delimiter codes are surfaced structurally; the encapsulated FC
 * frame (FC header + payload + FC CRC) needs FC-level, cross-frame class-of-service context and its own
 * CRC handling, so this codec keeps it verbatim as `fcFrame` hex (byte-perfect) rather than sub-decoding
 * it — the FC dissection is a later enrichment. FCoE carries no length field of its own: like other
 * Ethernet children it runs to the end of the frame, so the encapsulated FC frame is bounded by the
 * frame's last 4 bytes (the EOF trailer). Nothing (CRC, SOF/EOF) is recomputed on encode — a faithful
 * executor carries the delimiters and the FC CRC as-is — so a well-formed FCoE frame round-trips
 * byte-for-byte.
 */
export class FCoE extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (FCoE.#schemaCache ??= FCoE.#buildSchema())
    }

    /** Header length of the fixed FCoE header (Version + Reserved + SOF). */
    static readonly #HEADER_LEN: number = 14

    /** Trailer length of the fixed FCoE trailer (EOF + 3 reserved bytes). */
    static readonly #TRAILER_LEN: number = 4

    /**
     * Bytes available to FCoE within the Ethernet frame. FCoE has no length field — it runs to the end
     * of the frame — so the whole captured Ethernet payload is FCoE content (header + FC frame + trailer).
     */
    #available(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'FCoE ver=${version} sof=${sof} eof=${eof}',
            properties: {
                //Version — the high 4 bits of byte 0 (FC-BB-5 defines version 0).
                version: {
                    type: 'integer',
                    label: 'Version',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: FCoE): void {
                        this.instance.version.setValue(this.readBits(0, 1, 0, 4))
                    },
                    encode: function (this: FCoE): void {
                        const node: any = this.instance.version
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
                //Reserved — the low 4 bits of byte 0 (kept verbatim so any non-zero reserved nibble
                //round-trips). Shares byte 0 with Version; writeBits masks so the two never clobber.
                reservedFlags: {
                    type: 'integer',
                    label: 'Reserved',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: FCoE): void {
                        this.instance.reservedFlags.setValue(this.readBits(0, 1, 4, 4))
                    },
                    encode: function (this: FCoE): void {
                        const node: any = this.instance.reservedFlags
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
                        this.writeBits(0, 1, 4, 4, value)
                    }
                },
                //The 12 reserved bytes (bytes 1..12) of the FCoE header, kept verbatim.
                reserved: this.fieldHex('reserved', 1, 12, 'Reserved'),
                //Start Of Frame delimiter code (byte 13) — e.g. SOFi3 0x2e, SOFn3 0x36. Kept verbatim.
                sof: this.fieldUInt('sof', 13, 1, 'SOF'),
                //The encapsulated Fibre Channel frame: 24-byte FC header + FC payload + 4-byte FC CRC,
                //kept verbatim. Bounded by the frame's last 4 bytes (the EOF trailer) so the trailer is
                //not pulled into the FC frame; FCoE runs to the end of the Ethernet frame.
                fcFrame: {
                    type: 'string',
                    label: 'FC Frame',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: FCoE): void {
                        const available: number = this.#available()
                        //A trailer (EOF + 3 reserved) is present only when there is room for both the
                        //14-byte header and the 4-byte trailer; otherwise everything after the header is
                        //the (truncated) FC frame and there is no trailer.
                        const fcEnd: number = available >= FCoE.#HEADER_LEN + FCoE.#TRAILER_LEN
                            ? available - FCoE.#TRAILER_LEN
                            : available
                        this.instance.fcFrame.setValue(fcEnd > FCoE.#HEADER_LEN
                            ? BufferToHex(this.readBytes(FCoE.#HEADER_LEN, fcEnd - FCoE.#HEADER_LEN))
                            : '')
                    },
                    encode: function (this: FCoE): void {
                        const fcFrame: string = this.instance.fcFrame.getValue('')
                        if (fcFrame) this.writeBytes(FCoE.#HEADER_LEN, HexToBuffer(fcFrame))
                    }
                },
                //End Of Frame delimiter code (first trailer byte) — e.g. EOFn 0x41, EOFt 0x42. Kept
                //verbatim. Sits at a frame-length-dependent offset (right after the FC frame), so it is
                //located from the frame end on decode and from the FC frame length on encode.
                eof: {
                    type: 'integer',
                    label: 'EOF',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: FCoE): void {
                        const available: number = this.#available()
                        if (available < FCoE.#HEADER_LEN + FCoE.#TRAILER_LEN) return
                        this.instance.eof.setValue(BufferToUInt8(this.readBytes(available - FCoE.#TRAILER_LEN, 1)))
                    },
                    encode: function (this: FCoE): void {
                        const raw: number | undefined = this.instance.eof.getValue()
                        if (raw === undefined || raw === null) return
                        const node: any = this.instance.eof
                        let value: number = raw
                        if (value > 255) {
                            this.recordError(node.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        const fcLen: number = HexToBuffer(this.instance.fcFrame.getValue('')).length
                        this.writeBytes(FCoE.#HEADER_LEN + fcLen, UInt8ToBuffer(value))
                    }
                },
                //The 3 reserved bytes after EOF, kept verbatim. Located from the frame end on decode and
                //from the FC frame length on encode (right after the EOF byte).
                eofReserved: {
                    type: 'string',
                    label: 'Reserved',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: FCoE): void {
                        const available: number = this.#available()
                        if (available < FCoE.#HEADER_LEN + FCoE.#TRAILER_LEN) return
                        this.instance.eofReserved.setValue(BufferToHex(this.readBytes(available - 3, 3)))
                    },
                    encode: function (this: FCoE): void {
                        const eofReserved: string = this.instance.eofReserved.getValue('')
                        if (!eofReserved) return
                        const fcLen: number = HexToBuffer(this.instance.fcFrame.getValue('')).length
                        this.writeBytes(FCoE.#HEADER_LEN + fcLen + 1, HexToBuffer(eofReserved))
                    }
                }
            }
        }
    }

    public readonly id: string = 'fcoe'

    public readonly name: string = 'Fibre Channel over Ethernet'

    public readonly nickname: string = 'FCoE'

    public readonly matchKeys: string[] = ['ethertype:8906']

    public match(): boolean {
        //An Ethernet child selected by EtherType 0x8906 (stored as a lowercase 4-hex string). Require at
        //least the fixed 14-byte FCoE header to be present.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'eth') return false
        if (this.prevCodecModule.instance.etherType.getValue() !== '8906') return false
        return this.packet.length - this.startPos >= FCoE.#HEADER_LEN
    }

    //A leaf header — the encapsulated FC frame requires FC-level, cross-frame parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
