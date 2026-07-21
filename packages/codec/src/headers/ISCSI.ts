import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {CodecModule} from '../types/CodecModule'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * iSCSI — Internet Small Computer Systems Interface (RFC 7143), TCP port 3260. Every iSCSI PDU begins
 * with a fixed 48-byte Basic Header Segment (BHS):
 *   byte 0  : reserved bit (0x80) | Immediate bit I (0x40) | 6-bit Opcode (0x3f)
 *   byte 1  : Final/Transit bit F (0x80) | 7 opcode-specific flag bits
 *   bytes 2-3 : opcode-specific
 *   byte 4  : TotalAHSLength (count of 4-byte AHS words)
 *   bytes 5-7 : DataSegmentLength (24-bit)
 *   bytes 8-15 : LUN or opcode-specific
 *   bytes 16-19 : Initiator Task Tag
 *   bytes 20-47 : opcode-specific
 * Opcodes include 0x00 NOP-Out, 0x01 SCSI Command, 0x03 Login Request, 0x21 SCSI Response, 0x23 Login
 * Response. The BHS is followed by any AHS (TotalAHSLength*4 bytes), an optional header digest, the data
 * segment (DataSegmentLength bytes padded to a 4-byte boundary), and an optional data digest.
 *
 * Byte-perfect strategy (minimal slice): the semantically useful values are structured — opcode /
 * immediate / final / totalAHSLength / dataSegmentLength / initiatorTaskTag — and every other BHS byte is
 * kept verbatim as bounded opcode-specific hex, together covering all 48 bytes exactly once (no field
 * overlaps another, so reserved bits and opcode-specific fields round-trip untouched). DataSegmentLength
 * is honored when supplied (a crafted PDU may lie), else derived from the actual data segment. The AHS and
 * the (4-byte-padded) data segment follow, each bounded by the on-wire TCP payload (derived from the IP
 * length) so a lying length never reads past the datagram; the data segment's alignment padding is
 * consumed on decode and re-emitted as zeros on encode. This layer consumes exactly one PDU (BHS + AHS +
 * data + pad); trailing bytes — a header/data digest (negotiated, so not modelled) or a pipelined PDU —
 * are left to the codec's recursion / RawData. A well-formed PDU round-trips byte-for-byte.
 */
export class ISCSI extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (ISCSI.#schemaCache ??= ISCSI.#buildSchema())
    }

    /**
     * Bytes of TCP payload available to this iSCSI PDU from its start, clamped to the captured buffer.
     * The transport (TCP) carries no payload length, so the bound comes from the IP layer two hops back:
     * IPv4's total length or IPv6's payload length gives the absolute end of the L4 payload. Mirrors the
     * OSPF/GRE #available pattern so the AHS and data segment can be bounded by the real on-wire length
     * rather than trusting the length fields alone. Falls back to the captured bytes when no IP is found.
     * @private
     */
    #available(): number {
        const capped: number = this.packet.length - this.startPos
        const mods: CodecModule[] = this.prevCodecModules
        const ip: any = mods && mods.length >= 2 ? mods[mods.length - 2] : undefined
        if (!ip || !ip.instance) return capped
        const ipv4TotalLength: number = ip.instance.length.getValue(0)
        const ipv6PayloadLength: number = ip.instance.plen.getValue(0)
        let payloadEndAbs: number = 0
        if (ipv4TotalLength) payloadEndAbs = ip.startPos + ipv4TotalLength
        else if (ipv6PayloadLength) payloadEndAbs = ip.startPos + ip.length + ipv6PayloadLength
        if (payloadEndAbs > 0) {
            const available: number = payloadEndAbs - this.startPos
            if (available >= 0 && available < capped) return available
        }
        return capped
    }

    /** Length in bytes of the Additional Header Segments (TotalAHSLength is a 4-byte word count). */
    #ahsLength(): number {
        return this.instance.totalAHSLength.getValue(0) * 4
    }

    /** Header-relative offset where the data segment begins: after the 48-byte BHS and any AHS. */
    #dataStart(): number {
        return 48 + this.#ahsLength()
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'iSCSI opcode=${opcode} itt=${initiatorTaskTag}',
            properties: {
                //==== Basic Header Segment (48 bytes, RFC 7143 §11.1) ====
                //Byte 0: opcode (low 6 bits), Immediate bit (0x40), reserved bit (0x80). The three fields
                //cover byte 0 exactly, so every bit — including the reserved one — round-trips.
                opcode: {
                    type: 'integer',
                    label: 'Opcode',
                    minimum: 0,
                    maximum: 63,
                    decode: function (this: ISCSI): void {
                        this.instance.opcode.setValue(this.readBits(0, 1, 2, 6))
                    },
                    encode: function (this: ISCSI): void {
                        let value: number = this.instance.opcode.getValue(0)
                        if (value > 63) {
                            this.recordError(this.instance.opcode.getPath(), 'Maximum value is 63')
                            value = 63
                        }
                        if (value < 0) {
                            this.recordError(this.instance.opcode.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.opcode.setValue(value)
                        this.writeBits(0, 1, 2, 6, value)
                    }
                },
                immediate: {
                    type: 'boolean',
                    label: 'Immediate',
                    decode: function (this: ISCSI): void {
                        this.instance.immediate.setValue(!!this.readBits(0, 1, 1, 1))
                    },
                    encode: function (this: ISCSI): void {
                        const value: boolean = !!this.instance.immediate.getValue(false)
                        this.instance.immediate.setValue(value)
                        this.writeBits(0, 1, 1, 1, value ? 1 : 0)
                    }
                },
                //The single reserved bit of byte 0 (0x80), preserved verbatim.
                reserved: {
                    type: 'integer',
                    label: 'Reserved',
                    minimum: 0,
                    maximum: 1,
                    decode: function (this: ISCSI): void {
                        this.instance.reserved.setValue(this.readBits(0, 1, 0, 1))
                    },
                    encode: function (this: ISCSI): void {
                        this.writeBits(0, 1, 0, 1, this.instance.reserved.getValue(0) ? 1 : 0)
                    }
                },
                //Byte 1: Final/Transit bit (0x80) + 7 opcode-specific flag bits — together they cover byte 1.
                final: {
                    type: 'boolean',
                    label: 'Final',
                    decode: function (this: ISCSI): void {
                        this.instance.final.setValue(!!this.readBits(1, 1, 0, 1))
                    },
                    encode: function (this: ISCSI): void {
                        const value: boolean = !!this.instance.final.getValue(false)
                        this.instance.final.setValue(value)
                        this.writeBits(1, 1, 0, 1, value ? 1 : 0)
                    }
                },
                //The opcode-specific flag bits of byte 1 (0x7f), kept verbatim (e.g. Login's C/CSG/NSG,
                //SCSI Command's R/W/ATTR).
                opcodeSpecificFlags: {
                    type: 'integer',
                    label: 'Opcode-Specific Flags',
                    minimum: 0,
                    maximum: 127,
                    decode: function (this: ISCSI): void {
                        this.instance.opcodeSpecificFlags.setValue(this.readBits(1, 1, 1, 7))
                    },
                    encode: function (this: ISCSI): void {
                        let value: number = this.instance.opcodeSpecificFlags.getValue(0)
                        if (value > 127) {
                            this.recordError(this.instance.opcodeSpecificFlags.getPath(), 'Maximum value is 127')
                            value = 127
                        }
                        if (value < 0) {
                            this.recordError(this.instance.opcodeSpecificFlags.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.opcodeSpecificFlags.setValue(value)
                        this.writeBits(1, 1, 1, 7, value)
                    }
                },
                //Bytes 2-3, opcode-specific (e.g. Login Version-max / Version-min), kept verbatim.
                opcodeSpecific1: this.fieldHex('opcodeSpecific1', 2, 2, 'Opcode-Specific (bytes 2-3)'),
                //Byte 4: TotalAHSLength, a count of 4-byte AHS words; bounds where the data segment begins.
                totalAHSLength: this.fieldUInt('totalAHSLength', 4, 1, 'Total AHS Length'),
                //Bytes 5-7: DataSegmentLength (24-bit). Honored when supplied (a crafted PDU may lie), else
                //derived from the actual data segment length.
                dataSegmentLength: {
                    type: 'integer',
                    label: 'Data Segment Length',
                    minimum: 0,
                    maximum: 16777215,
                    decode: function (this: ISCSI): void {
                        this.instance.dataSegmentLength.setValue(this.readBits(5, 3, 0, 24))
                    },
                    encode: function (this: ISCSI): void {
                        const provided: number | undefined = this.instance.dataSegmentLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.dataSegment.getValue('')).length
                        if (value > 16777215) {
                            this.recordError(this.instance.dataSegmentLength.getPath(), 'Maximum value is 16777215')
                            value = 16777215
                        }
                        if (value < 0) {
                            this.recordError(this.instance.dataSegmentLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.dataSegmentLength.setValue(value)
                        this.writeBits(5, 3, 0, 24, value)
                    }
                },
                //Bytes 8-15: LUN or opcode-specific fields (e.g. Login's ISID + TSIH), kept verbatim.
                lun: this.fieldHex('lun', 8, 8, 'LUN / Opcode-Specific (bytes 8-15)'),
                //Bytes 16-19: Initiator Task Tag, an opaque tag matching a response to its request.
                initiatorTaskTag: this.fieldHex('initiatorTaskTag', 16, 4, 'Initiator Task Tag'),
                //Bytes 20-47: the rest of the opcode-specific header (e.g. Login's CID / CmdSN / ExpStatSN),
                //kept verbatim.
                opcodeSpecific2: this.fieldHex('opcodeSpecific2', 20, 28, 'Opcode-Specific (bytes 20-47)'),
                //==== Additional Header Segments (RFC 7143 §11.2), kept verbatim ====
                //Present only when TotalAHSLength > 0. Bounded by the TCP payload so a lying count can't
                //read past the datagram.
                ahs: {
                    type: 'string',
                    label: 'Additional Header Segments',
                    minLength: 0,
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: ISCSI): void {
                        const ahsLength: number = this.#ahsLength()
                        if (ahsLength <= 0) return
                        const available: number = this.#available()
                        const length: number = Math.min(ahsLength, Math.max(0, available - 48))
                        if (length > 0) this.instance.ahs.setValue(BufferToHex(this.readBytes(48, length)))
                    },
                    encode: function (this: ISCSI): void {
                        if (this.instance.ahs.isUndefined()) return
                        const ahs: string = this.instance.ahs.getValue('')
                        if (ahs) this.writeBytes(48, HexToBuffer(ahs))
                    }
                },
                //==== Data segment (RFC 7143 §11.5), kept verbatim ====
                //DataSegmentLength bytes after the BHS + AHS, padded to a 4-byte boundary with zeros. The
                //data is stored unpadded; the padding is consumed on decode and re-emitted as zeros on
                //encode (well-formed PDUs pad with zeros) so this layer consumes exactly one PDU's header +
                //data + pad and leaves any digest / pipelined PDU to the codec's recursion. Bounded by the
                //TCP payload so a lying DataSegmentLength can't read past the datagram.
                dataSegment: {
                    type: 'string',
                    label: 'Data Segment',
                    minLength: 0,
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: ISCSI): void {
                        const dataSegmentLength: number = this.instance.dataSegmentLength.getValue(0)
                        const start: number = this.#dataStart()
                        const available: number = this.#available()
                        const room: number = Math.max(0, available - start)
                        const realLength: number = Math.min(dataSegmentLength, room)
                        this.instance.dataSegment.setValue(realLength > 0 ? BufferToHex(this.readBytes(start, realLength)) : '')
                        //Consume the 4-byte-alignment padding so headerLength spans the whole PDU and the
                        //next PDU / digest starts at the right offset. Reading (non-dry) extends the span.
                        const padded: number = dataSegmentLength + ((4 - (dataSegmentLength % 4)) % 4)
                        const consume: number = Math.min(padded, room)
                        if (consume > realLength) this.readBytes(start, consume)
                    },
                    encode: function (this: ISCSI): void {
                        const body: Buffer = HexToBuffer(this.instance.dataSegment.getValue(''))
                        const start: number = this.#dataStart()
                        if (body.length) this.writeBytes(start, body)
                        //Pad the data segment to a 4-byte boundary with zeros (RFC 7143 §11.5).
                        const pad: number = (4 - (body.length % 4)) % 4
                        if (pad > 0) this.writeBytes(start + body.length, Buffer.alloc(pad, 0))
                    }
                }
            }
        }
    }

    public readonly id: string = 'iscsi'

    public readonly name: string = 'Internet Small Computer Systems Interface'

    public readonly nickname: string = 'iSCSI'

    public readonly matchKeys: string[] = ['tcpport:3260']

    public match(): boolean {
        //iSCSI rides TCP port 3260 (selected via the tcpport:3260 bucket). This stays a port-bucket
        //protocol: matchKeys only, NO heuristicFallback — the BHS has no magic signature, so non-iSCSI
        //traffic on 3260 must fall through to raw. Require a full 48-byte BHS of TCP payload to be present
        //(bounded by the real on-wire length, not the whole frame, so ethernet padding is not mistaken
        //for a BHS).
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        return this.#available() >= 48
    }

    //A leaf header — AHS / data-segment sub-structure (SCSI CDBs, login key=value pairs) is kept verbatim.
    public readonly demuxProducers: DemuxProducer[] = []

}
