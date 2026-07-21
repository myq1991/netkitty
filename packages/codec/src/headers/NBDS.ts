import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt16} from '../helper/BufferToNumber'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * NBDS — NetBIOS Datagram Service (RFC 1002 §4.4), the NetBIOS-over-TCP/IP datagram service on UDP 138.
 * Every NBDS packet opens with a fixed 10-byte common prefix — a 1-byte Message Type, a 1-byte Flags
 * octet (MORE/FIRST fragment bits + 2-bit Source End-Node Type + reserved bits), a 2-byte Datagram ID,
 * the 4-byte Source IP and the 2-byte Source Port of the originating node.
 *
 * What follows the prefix depends on the Message Type. The DIRECT_UNIQUE (0x10), DIRECT_GROUP (0x11)
 * and BROADCAST (0x12) datagrams add a 2-byte Datagram Length and a 2-byte Packet Offset (fragmentation
 * offset), then the second-level-encoded Source and Destination NetBIOS names followed by the user data
 * (an SMB mailslot payload, e.g. a browser announcement). DATAGRAM ERROR (0x13) carries a 1-byte error
 * code; the QUERY messages (0x14/0x15/0x16) carry only a destination name. So only the Direct/Broadcast
 * types have the Datagram-Length / Packet-Offset words — they are structured for those types and left out
 * of the byte stream otherwise (mirroring COTP's DT-only fields).
 *
 * The names + user data (for Direct/Broadcast) or the type-specific remainder (for the other types) are
 * kept verbatim as `body` hex, bounded by the UDP payload length so trailing bytes are not absorbed:
 * decoding the second-level NetBIOS names and handing the user data to SMB is a later enrichment. Message
 * Type is stored as the raw octet (fieldUInt — no enum, so a crafted/unknown type still round-trips) and
 * the Datagram Length is honored on encode when supplied, else derived from the body. A well-formed
 * datagram of any type round-trips byte-for-byte.
 */
export class NBDS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (NBDS.#schemaCache ??= NBDS.#buildSchema())
    }

    /** The DIRECT_UNIQUE / DIRECT_GROUP / BROADCAST types (0x10-0x12) carry the length + offset words and names. */
    static #isDirect(msgType: number): boolean {
        return msgType >= 0x10 && msgType <= 0x12
    }

    /** End of this datagram within the captured bytes: bounded by the parent UDP payload (udp.length − 8). */
    #payloadEnd(): number {
        let end: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpLength: number = prev.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < end) end = udpLength - 8
        }
        return end < 0 ? 0 : end
    }

    /** The offset where the type-specific body begins: after the length/offset words for Direct types, else right after the 10-byte prefix. */
    #bodyStart(): number {
        return NBDS.#isDirect(this.instance.msgType.getValue(0)) ? 14 : 10
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'NBDS type=${msgType} id=${dgmId}',
            properties: {
                //The Message Type octet, kept raw (0x10 DIRECT_UNIQUE, 0x11 DIRECT_GROUP, 0x12 BROADCAST,
                //0x13 DATAGRAM ERROR, 0x14 QUERY REQUEST, 0x15/0x16 QUERY RESPONSE, …). No enum: an unknown
                //or crafted type must still decode and re-encode.
                msgType: this.fieldUInt('msgType', 0, 1, 'Message Type'),
                //The Flags octet, kept whole so the MORE/FIRST fragment bits, the 2-bit Source End-Node
                //Type and the reserved bits all round-trip untouched.
                flags: this.fieldUInt('flags', 1, 1, 'Flags'),
                dgmId: this.fieldUInt('dgmId', 2, 2, 'Datagram ID'),
                sourceIP: this.fieldIPv4('sourceIP', 4, 'Source IP'),
                sourcePort: this.fieldUInt('sourcePort', 8, 2, 'Source Port'),
                //Direct/Broadcast only: the 2-byte Datagram Length — the count of bytes that follow the
                //Packet Offset (the NetBIOS names + user data). Honored on encode when supplied, else
                //derived from the body. Meaningless for other types (not present on the wire — left 0).
                dgmLength: {
                    type: 'integer',
                    label: 'Datagram Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: NBDS): void {
                        if (!NBDS.#isDirect(this.instance.msgType.getValue(0))) return
                        this.instance.dgmLength.setValue(BufferToUInt16(this.readBytes(10, 2)))
                    },
                    encode: function (this: NBDS): void {
                        if (!NBDS.#isDirect(this.instance.msgType.getValue(0))) return
                        const provided: number | undefined = this.instance.dgmLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.dgmLength.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        this.instance.dgmLength.setValue(value)
                        this.writeBytes(10, UInt16ToBuffer(value))
                    }
                },
                //Direct/Broadcast only: the 2-byte Packet Offset (fragmentation offset within the datagram).
                packetOffset: {
                    type: 'integer',
                    label: 'Packet Offset',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: NBDS): void {
                        if (!NBDS.#isDirect(this.instance.msgType.getValue(0))) return
                        this.instance.packetOffset.setValue(BufferToUInt16(this.readBytes(12, 2)))
                    },
                    encode: function (this: NBDS): void {
                        if (!NBDS.#isDirect(this.instance.msgType.getValue(0))) return
                        let value: number = this.instance.packetOffset.getValue(0)
                        if (value > 65535) {
                            this.recordError(this.instance.packetOffset.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.packetOffset.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.packetOffset.setValue(value)
                        this.writeBytes(12, UInt16ToBuffer(value))
                    }
                },
                //The type-specific remainder kept verbatim: for Direct/Broadcast it is the second-level
                //encoded Source + Destination NetBIOS names followed by the user data (SMB mailslot); for
                //the error/query types it is their small type-specific tail. Bounded by the UDP payload
                //length so any trailing bytes are left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: NBDS): void {
                        const start: number = this.#bodyStart()
                        const end: number = this.#payloadEnd()
                        this.instance.body.setValue(end > start ? BufferToHex(this.readBytes(start, end - start)) : '')
                    },
                    encode: function (this: NBDS): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(this.#bodyStart(), HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'nbds'

    public readonly name: string = 'NetBIOS Datagram Service'

    public readonly nickname: string = 'NBDS'

    public readonly matchKeys: string[] = ['udpport:138']

    public match(): boolean {
        //NBDS rides UDP port 138 (selected via the udpport:138 bucket). Port-bucket only, NO
        //heuristicFallback — the header has no strong content signature, so non-NBDS traffic on 138 must
        //fall through to raw. Require at least the 10-byte common prefix within the UDP payload.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        const available: number = this.#payloadEnd()
        if (available < 10) return false
        //Direct/Broadcast types (0x10-0x12) carry a 2-byte Datagram Length + 2-byte Packet Offset that are
        //always re-emitted on encode, so require the full 14-byte fixed header. A shorter direct datagram
        //could not round-trip those words (encode would sprout bytes the wire never had), so leave it to
        //RawData rather than claim it. Non-direct types only need the 10-byte common prefix.
        if (NBDS.#isDirect(this.readBytes(0, 1, true)[0]) && available < 14) return false
        return true
    }

    //A leaf header — the NetBIOS names and the SMB mailslot user data are kept verbatim and decoded later.
    public readonly demuxProducers: DemuxProducer[] = []

}
