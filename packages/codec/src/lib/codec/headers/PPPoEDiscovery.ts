import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One PPPoE Discovery tag: a 16-bit Type, its 16-bit Length, and its verbatim hex Value. */
type PPPoETag = {type: number, length?: number, value: string}

/**
 * PPPoE Discovery Stage (RFC 2516), carried directly in an Ethernet II frame with EtherType 0x8863 (an
 * Ethernet child — no IP/UDP). The 6-byte header is a Version (high 4 bits, 1) + Type (low 4 bits, 1)
 * octet, a 1-byte Code (0x09 PADI, 0x07 PADO, 0x19 PADR, 0x65 PADS, 0xa7 PADT), a 2-byte Session ID,
 * and a 2-byte Length that counts only the tag payload that follows. The payload is a flat sequence of
 * TLV tags — Type (2 bytes: 0x0101 Service-Name, 0x0102 AC-Name, 0x0103 Host-Uniq, 0x0104 AC-Cookie,
 * 0x0000 End-Of-List) + Length (2 bytes, the value byte count) + Length value bytes — bounded by the
 * header Length field.
 *
 * Tags are carried generically (type + honored per-tag length + verbatim hex value) so every tag —
 * including opaque/vendor tags — round-trips byte-for-byte; per-tag semantic decoding is a later
 * enrichment. The header Length is honored when supplied (a crafted frame may lie) and otherwise
 * derived from the on-wire tag bytes. The tag walk is bounded by that Length; any trailing bytes (an
 * Ethernet minimum-frame pad) are kept verbatim in `padding` so the frame reproduces exactly. A leaf
 * header — the Discovery stage carries no encapsulated payload.
 */
export class PPPoEDiscovery extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (PPPoEDiscovery.#schemaCache ??= PPPoEDiscovery.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'PPPoE Discovery code=${code} session=${sessionId}',
            properties: {
                //Byte 0 high nibble: PPPoE Version (1). Written MSB-first; shares byte 0 with Type
                //(writeBits masks each field so they never clobber).
                version: {
                    type: 'integer', label: 'Version', minimum: 0, maximum: 15,
                    decode: function (this: PPPoEDiscovery): void {
                        this.instance.version.setValue(this.readBits(0, 1, 0, 4))
                    },
                    encode: function (this: PPPoEDiscovery): void {
                        const value: number = this.instance.version.getValue(1)
                        this.instance.version.setValue(value)
                        this.writeBits(0, 1, 0, 4, value)
                    }
                },
                //Byte 0 low nibble: PPPoE Type (1).
                type: {
                    type: 'integer', label: 'Type', minimum: 0, maximum: 15,
                    decode: function (this: PPPoEDiscovery): void {
                        this.instance.type.setValue(this.readBits(0, 1, 4, 4))
                    },
                    encode: function (this: PPPoEDiscovery): void {
                        const value: number = this.instance.type.getValue(1)
                        this.instance.type.setValue(value)
                        this.writeBits(0, 1, 4, 4, value)
                    }
                },
                //Code (byte 1): 0x09 PADI, 0x07 PADO, 0x19 PADR, 0x65 PADS, 0xa7 PADT.
                code: this.fieldUInt('code', 1, 1, 'Code'),
                //Session ID (bytes 2-3): 0x0000 during discovery until the AC assigns it in PADS.
                sessionId: this.fieldUInt('sessionId', 2, 2, 'Session ID'),
                length: {
                    type: 'integer',
                    label: 'Payload Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: PPPoEDiscovery): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(4, 2)))
                    },
                    encode: function (this: PPPoEDiscovery): void {
                        //Length counts only the tag payload (not the 6-byte header). Honored when supplied
                        //(a crafted frame may lie); else derived from the actual on-wire tag bytes, which is
                        //what the tags field emits — sum of (4-byte tag header + value byte count) per tag.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number
                        if (provided !== undefined && provided !== null) {
                            value = provided
                        } else {
                            const tags: PPPoETag[] = this.instance.tags.getValue([])
                            let total: number = 0
                            for (const tag of (tags ? tags : [])) {
                                total += 4 + HexToBuffer(tag.value ? tag.value : '').length
                            }
                            value = total
                        }
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(4, UInt16ToBuffer(value))
                    }
                },
                tags: {
                    type: 'array',
                    label: 'Tags',
                    items: {
                        type: 'object',
                        label: 'Tag',
                        properties: {
                            type: {type: 'integer', label: 'Type', minimum: 0, maximum: 65535},
                            length: {type: 'integer', label: 'Length', minimum: 0, maximum: 65535, hidden: true},
                            value: {type: 'string', label: 'Value', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: PPPoEDiscovery): void {
                        //Bound the tag walk by the header Length (from offset 6), clamped down to the bytes
                        //actually present in the frame so a lying Length can't read past the buffer.
                        const available: number = this.packet.length - this.startPos
                        let end: number = 6 + this.instance.length.getValue(0)
                        if (end > available) end = available
                        if (end < 6) end = 6
                        const tags: PPPoETag[] = []
                        let offset: number = 6
                        while (offset + 4 <= end) {
                            const type: number = BufferToUInt16(this.readBytes(offset, 2))
                            const length: number = BufferToUInt16(this.readBytes(offset + 2, 2))
                            //A value that overruns the bounded region (truncation) is not consumed — stop and
                            //leave the remaining bytes to `padding`, keeping the round-trip exact.
                            if (offset + 4 + length > end) break
                            const value: string = length > 0 ? BufferToHex(this.readBytes(offset + 4, length)) : ''
                            tags.push({type: type, length: length, value: value})
                            offset += 4 + length
                        }
                        this.instance.tags.setValue(tags)
                        //Trailing bytes after the last consumed tag (Ethernet minimum-frame padding, or a
                        //truncated tag) are kept verbatim so the frame is reproduced exactly.
                        this.instance.padding.setValue(offset < available ? BufferToHex(this.readBytes(offset, available - offset)) : '')
                    },
                    encode: function (this: PPPoEDiscovery): void {
                        const tags: PPPoETag[] = this.instance.tags.getValue([])
                        let offset: number = 6
                        if (tags) {
                            for (let i: number = 0; i < tags.length; i++) {
                                const tag: PPPoETag = tags[i]
                                const value: Buffer = HexToBuffer(tag.value ? tag.value : '')
                                //Per-tag Length is honored when supplied (a crafted tag may lie about its
                                //declared length); else derived from the actual value byte count. The value
                                //bytes are always written verbatim regardless of the declared Length.
                                let length: number = (tag.length !== undefined && tag.length !== null) ? tag.length : value.length
                                if (length > 65535) {
                                    this.recordError(`tags[${i}].length`, 'Maximum value is 65535')
                                    length = 65535
                                }
                                this.writeBytes(offset, UInt16ToBuffer(tag.type ? tag.type : 0))
                                this.writeBytes(offset + 2, UInt16ToBuffer(length))
                                offset += 4
                                if (value.length) {
                                    this.writeBytes(offset, value)
                                    offset += value.length
                                }
                            }
                        }
                        const padding: string = this.instance.padding.getValue('')
                        if (padding) this.writeBytes(offset, HexToBuffer(padding))
                    }
                },
                //Ethernet minimum-frame padding after the tags, kept verbatim. No codec of its own — it is
                //set/read by the `tags` field (which owns the single offset walk); this entry is metadata so
                //the editor sees the padding bytes.
                padding: {
                    type: 'string',
                    label: 'Padding',
                    contentEncoding: StringContentEncodingEnum.HEX
                }
            }
        }
    }

    public readonly id: string = 'pppoe-disc'

    public readonly name: string = 'PPP-over-Ethernet Discovery'

    public readonly nickname: string = 'PPPoED'

    public readonly matchKeys: string[] = ['ethertype:8863']

    public match(): boolean {
        //An Ethernet child selected by EtherType 0x8863 (stored as a lower-case 4-hex string, as
        //eth.etherType / a VLAN's inner etherType). Not restricted to a direct 'eth' parent so a
        //VLAN-tagged discovery frame still matches. Require the 6-byte fixed header.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.instance.etherType.getValue() !== '8863') return false
        return this.packet.length - this.startPos >= 6
    }

    //A leaf header — the Discovery stage carries no encapsulated payload (session data uses EtherType
    //0x8864, a separate header).
    public readonly demuxProducers: DemuxProducer[] = []

}
