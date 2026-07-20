import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * C37.118 — IEEE Std C37.118.2 synchrophasor data transfer (PMU/PDC), typically TCP port 4712 and UDP
 * port 4713. Every frame shares a 14-byte common header: SYNC (a 0xAA lead-in byte, then a byte holding
 * a reserved bit, a 3-bit Frame Type — data / header / config-1 / config-2 / command / config-3 — and a
 * 4-bit Version), a FRAMESIZE (total frame length including the check word), an IDCODE (data stream id),
 * a SOC (second-of-century UNIX time), and a FRACSEC (an 8-bit time-quality byte plus a 24-bit fraction
 * of second). It ends with a 2-byte CHK (CRC-CCITT over the whole frame). Everything is big-endian.
 *
 * The frame body between the header and the CHK is frame-type-specific (a configuration frame defines
 * the data layout for the data frames that follow — cross-frame state, not a single-packet concern), so
 * this codec keeps the body verbatim as `body` hex, bounded by FRAMESIZE, and keeps the CHK verbatim
 * (never recomputed). A well-formed frame round-trips byte-for-byte.
 */
export class C37118 extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (C37118.#schemaCache ??= C37118.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'C37.118 type=${sync.frameType} id=${idcode}',
            properties: {
                leadIn: this.fieldHex('leadIn', 0, 1, 'Lead-in (0xAA)'),
                //SYNC byte 1 (MSB first): reserved bit, 3-bit Frame Type, 4-bit Version.
                sync: {
                    type: 'object',
                    label: 'SYNC',
                    properties: {
                        reserved: {
                            type: 'integer', label: 'Reserved', minimum: 0, maximum: 1, hidden: true,
                            decode: function (this: C37118): void { this.instance.sync.reserved.setValue(this.readBits(1, 1, 0, 1)) },
                            encode: function (this: C37118): void { this.writeBits(1, 1, 0, 1, this.instance.sync.reserved.getValue(0)) }
                        },
                        frameType: {
                            type: 'integer', label: 'Frame Type', minimum: 0, maximum: 7,
                            decode: function (this: C37118): void { this.instance.sync.frameType.setValue(this.readBits(1, 1, 1, 3)) },
                            encode: function (this: C37118): void { this.writeBits(1, 1, 1, 3, this.instance.sync.frameType.getValue(0)) }
                        },
                        version: {
                            type: 'integer', label: 'Version', minimum: 0, maximum: 15,
                            decode: function (this: C37118): void { this.instance.sync.version.setValue(this.readBits(1, 1, 4, 4)) },
                            encode: function (this: C37118): void { this.writeBits(1, 1, 4, 4, this.instance.sync.version.getValue(1)) }
                        }
                    }
                },
                framesize: {
                    type: 'integer',
                    label: 'Frame Size',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: C37118): void {
                        this.instance.framesize.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: C37118): void {
                        //Honored when supplied (a crafted frame may lie); else derived from the actual
                        //body + CHK (FRAMESIZE is the total frame length: 14-byte header + body + CHK).
                        const provided: number | undefined = this.instance.framesize.getValue()
                        const value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 14 + HexToBuffer(this.instance.body.getValue('')).length + HexToBuffer(this.instance.chk.getValue('')).length
                        this.instance.framesize.setValue(value)
                        this.writeBytes(2, UInt16ToBuffer(value))
                    }
                },
                idcode: this.fieldUInt('idcode', 4, 2, 'ID Code'),
                soc: this.fieldUInt('soc', 6, 4, 'SOC (Second of Century)'),
                timeQuality: this.fieldUInt('timeQuality', 10, 1, 'Time Quality'),
                fractionOfSecond: {
                    type: 'integer',
                    label: 'Fraction of Second',
                    minimum: 0,
                    maximum: 16777215,
                    decode: function (this: C37118): void { this.instance.fractionOfSecond.setValue(this.readBits(11, 3, 0, 24)) },
                    encode: function (this: C37118): void { this.writeBits(11, 3, 0, 24, this.instance.fractionOfSecond.getValue(0)) }
                },
                //Frame-type-specific body, kept verbatim, and the trailing CHK. The body master reads
                //FRAMESIZE (which includes the 2-byte CHK) to place the CHK at the end of the frame.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: C37118): void {
                        const remaining: number = this.packet.length - this.startPos
                        const framesize: number = this.instance.framesize.getValue(0)
                        let frameEnd: number = framesize
                        if (frameEnd > remaining || frameEnd < 16) frameEnd = remaining
                        const chkStart: number = frameEnd - 2
                        if (chkStart >= 14) {
                            this.instance.body.setValue(chkStart > 14 ? BufferToHex(this.readBytes(14, chkStart - 14)) : '')
                            this.instance.chk.setValue(BufferToHex(this.readBytes(chkStart, 2)))
                        } else {
                            //Too short for a CHK: keep whatever remains as body, no check word.
                            this.instance.body.setValue(remaining > 14 ? BufferToHex(this.readBytes(14, remaining - 14)) : '')
                            this.instance.chk.setValue('')
                        }
                    },
                    encode: function (this: C37118): void {
                        const body: string = this.instance.body.getValue('')
                        const bodyBuffer: Buffer = HexToBuffer(body)
                        if (bodyBuffer.length) this.writeBytes(14, bodyBuffer)
                        const chk: string = this.instance.chk.getValue('')
                        if (chk) this.writeBytes(14 + bodyBuffer.length, HexToBuffer(chk))
                    }
                },
                //The check word (CRC-CCITT), honored verbatim (never recomputed) — populated by the body
                //master since its offset (FRAMESIZE - 2) is frame-length dependent.
                chk: {type: 'string', label: 'Check', contentEncoding: StringContentEncodingEnum.HEX}
            }
        }
    }

    public readonly id: string = 'c37118'

    public readonly name: string = 'IEEE C37.118 Synchrophasor'

    public readonly nickname: string = 'C37.118'

    public readonly matchKeys: string[] = ['tcpport:4712', 'udpport:4713']

    public match(): boolean {
        //C37.118 rides on TCP 4712 / UDP 4713. Require the common header + CHK (16 bytes) and the 0xAA
        //SYNC lead-in signature so non-C37.118 traffic on those ports falls through to raw.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp' && this.prevCodecModule.id !== 'udp') return false
        if (this.packet.length - this.startPos < 16) return false
        return this.readBytes(0, 1, true)[0] === 0xaa
    }

    //A leaf header — configuration/data frame bodies are stateful (a config frame defines later data
    //frames), which belongs to a higher layer.
    public readonly demuxProducers: DemuxProducer[] = []

}
