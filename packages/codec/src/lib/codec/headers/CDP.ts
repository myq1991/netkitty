import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * CDP — Cisco Discovery Protocol, carried in an 802.3 frame over LLC/SNAP with OUI 0x00000C and PID
 * 0x2000. A 4-byte header — Version (1), Time-to-Live (1) and a 2-byte Checksum — is followed by a
 * sequence of TLVs, each a 2-byte Type + 2-byte Length (the whole TLV octet count including this 4-byte
 * TLV header) + value. Common types: 0x0001 Device ID, 0x0002 Addresses, 0x0003 Port ID, 0x0004
 * Capabilities, 0x0005 Software Version, 0x0006 Platform.
 *
 * The TLV values are kept verbatim as hex (device names, address lists and capability bitmaps need no
 * form structure), the Checksum is honored verbatim (never recomputed), and the TLV walk is bounded by
 * the captured bytes so a corrupt Length can't run past the frame. A well-formed CDP frame round-trips
 * byte-for-byte.
 */
export class CDP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (CDP.#schemaCache ??= CDP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'CDP v${version} ttl=${ttl}',
            properties: {
                version: this.fieldUInt('version', 0, 1, 'Version'),
                ttl: this.fieldUInt('ttl', 1, 1, 'TTL'),
                //Honored verbatim — the ones-complement checksum is never recomputed, so a captured frame
                //round-trips byte-for-byte.
                checksum: this.fieldHex('checksum', 2, 2, 'Checksum'),
                tlvs: {
                    type: 'array',
                    label: 'TLVs',
                    items: {
                        type: 'object',
                        properties: {
                            type: {type: 'integer', label: 'Type', minimum: 0, maximum: 65535},
                            length: {type: 'integer', label: 'Length', minimum: 0, maximum: 65535},
                            value: {type: 'string', label: 'Value', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: CDP): void {
                        const available: number = this.packet.length - this.startPos
                        const tlvs: {type: number, length: number, value: string}[] = []
                        let offset: number = 4
                        while (offset + 4 <= available) {
                            const type: number = BufferToUInt16(this.readBytes(offset, 2, true))
                            const length: number = BufferToUInt16(this.readBytes(offset + 2, 2, true))
                            //A Length below the 4-byte TLV header is malformed — record and stop.
                            if (length < 4) {
                                this.recordError(this.instance.tlvs.getPath(), `Invalid TLV length ${length}`)
                                break
                            }
                            let end: number = offset + length
                            if (end > available) end = available
                            const value: string = end > offset + 4 ? BufferToHex(this.readBytes(offset + 4, end - (offset + 4))) : ''
                            tlvs.push({type: type, length: length, value: value})
                            offset += length
                        }
                        //Mark the whole consumed TLV region so an empty-value trailing TLV is not re-decoded
                        //as trailing RawData and duplicated on encode (the headers above are dryRun peeks).
                        const consumedEnd: number = offset < available ? offset : available
                        if (consumedEnd > 4) this.readBytes(4, consumedEnd - 4)
                        this.instance.tlvs.setValue(tlvs)
                    },
                    encode: function (this: CDP): void {
                        const tlvs: any[] | undefined = this.instance.tlvs.getValue()
                        if (!Array.isArray(tlvs)) return
                        let offset: number = 4
                        for (const tlv of tlvs) {
                            const valueBuffer: Buffer = HexToBuffer(tlv && tlv.value ? String(tlv.value) : '')
                            const providedLength: number = Number(tlv && tlv.length)
                            const lengthValue: number = (Number.isFinite(providedLength) && providedLength > 0)
                                ? providedLength
                                : 4 + valueBuffer.length
                            const type: number = Number(tlv && tlv.type) || 0
                            this.writeBytes(offset, UInt16ToBuffer(type & 0xffff))
                            this.writeBytes(offset + 2, UInt16ToBuffer(lengthValue > 65535 ? 65535 : lengthValue))
                            if (valueBuffer.length) this.writeBytes(offset + 4, valueBuffer)
                            offset += 4 + valueBuffer.length
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'cdp'

    public readonly name: string = 'Cisco Discovery Protocol'

    public readonly nickname: string = 'CDP'

    public readonly matchKeys: string[] = ['snapoui:00000c2000']

    public match(): boolean {
        //A SNAP child under Cisco OUI 0x00000C + PID 0x2000. Re-verify the OUI/PID off the SNAP parent
        //rather than trusting the key alone, and require the 4-byte CDP header.
        const prev: any = this.prevCodecModule
        if (!prev || prev.id !== 'snap') return false
        if (prev.instance.oui.getValue('') !== '00000c' || prev.instance.etherType.getValue('') !== '2000') return false
        return this.packet.length - this.startPos >= 4
    }

    //A leaf — CDP TLVs carry no encapsulated protocol.
    public readonly demuxProducers: DemuxProducer[] = []

}
