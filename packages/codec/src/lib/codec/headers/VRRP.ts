import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToUInt8, BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {BufferToIPv4} from '../../helper/BufferToIP'
import {IPv4ToBuffer} from '../../helper/IPToBuffer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'

/**
 * VRRP — Virtual Router Redundancy Protocol (v2 RFC 3768, v3 RFC 5798), carried directly over IP as
 * protocol 112. A fixed 8-byte header — Version (high nibble of byte 0) + Type (low nibble), Virtual
 * Router ID, Priority, Count of addresses, then two version-specific bytes, then a Checksum — followed
 * by the advertised virtual IP addresses (4-byte IPv4 each). In v2 bytes 4/5 are Auth Type / whole-second
 * Advertisement Interval and (with Auth Type 1) 8 trailing bytes of authentication data follow the
 * address list; in v3 bytes 4/5 are a reserved nibble + 12-bit Max Advertisement Interval (centiseconds).
 *
 * The version is the high nibble of byte 0 and selects how bytes 4-5 and the trailer are interpreted;
 * version-specific fields no-op when the decoded version does not match, so on encode each octet is
 * written by exactly one field — a well-formed advertisement round-trips byte-for-byte. The checksum is
 * honored verbatim (not recomputed — it differs by version and, in v3, covers an IP pseudo-header).
 */
export class VRRP extends BaseHeader {

    /**
     * Bytes available to this header within the enclosing IP layer's payload. Mirrors the IP-carried
     * pattern: for IPv4 the payload is (Total Length - IP header length); for IPv6 it is the Payload
     * Length field. Falls back to the raw remaining buffer when there is no IP layer beneath (e.g. a
     * malformed stack or a standalone decode), so match() and the address loop stay bounded.
     * @private
     */
    #available(): number {
        if (!this.prevCodecModule) return this.packet.length - this.startPos
        const version: number = this.prevCodecModule.instance.version.getValue(0)
        if (version === 4) {
            const ipTotalLength: number = this.prevCodecModule.instance.length.getValue(0)
            const available: number = ipTotalLength - this.prevCodecModule.length
            return available > 0 ? available : this.packet.length - this.startPos
        }
        if (version === 6) {
            const payloadLength: number = this.prevCodecModule.instance.plen.getValue(0)
            return payloadLength > 0 ? payloadLength : this.packet.length - this.startPos
        }
        return this.packet.length - this.startPos
    }

    static #schemaCache: ProtocolJSONSchema | undefined

    //Class-cached SCHEMA: field closures are plain functions taking dynamic `this` via .call(this), so
    //the structure is shareable and never rebuilt per packet. VRRP carries both v2 (RFC 3768) and v3
    //(RFC 5798) advertisements; the version is the high nibble of byte 0 and selects how bytes 4-5 and
    //the optional trailer are interpreted. Version-specific fields no-op when the decoded version does
    //not match, so each octet is written by exactly one field on encode (byte-perfect round-trip).
    public get SCHEMA(): ProtocolJSONSchema {
        return (VRRP.#schemaCache ??= VRRP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'VRRP v${version} vrid=${vrid} prio=${priority}',
            properties: {
                version: {
                    type: 'integer',
                    label: 'Version',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: VRRP): void {
                        this.instance.version.setValue(this.readBits(0, 1, 0, 4))
                        const version: number = this.instance.version.getValue(0)
                        if (version !== 2 && version !== 3) this.recordError(this.instance.version.getPath(), 'VRRP version should be 2 or 3')
                    },
                    encode: function (this: VRRP): void {
                        let version: number = this.instance.version.getValue(2, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        version = version > 15 ? 15 : version
                        version = version < 0 ? 0 : version
                        this.instance.version.setValue(version)
                        this.writeBits(0, 1, 0, 4, version)
                    }
                },
                type: {
                    type: 'integer',
                    label: 'Type',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: VRRP): void {
                        this.instance.type.setValue(this.readBits(0, 1, 4, 4))
                    },
                    encode: function (this: VRRP): void {
                        const type: number = this.instance.type.getValue(1, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        this.instance.type.setValue(type)
                        this.writeBits(0, 1, 4, 4, type)
                    }
                },
                vrid: this.fieldUInt('vrid', 1, 1, 'Virtual Router ID'),
                priority: this.fieldUInt('priority', 2, 1, 'Priority'),
                count: this.fieldUInt('count', 3, 1, 'Count IP Addrs'),
                authType: {
                    type: 'integer',
                    label: 'Auth Type',
                    minimum: 0,
                    maximum: 255,
                    //v2 only: byte 4 is the Authentication Type (RFC 3768 §5.3.6). In v3 byte 4 holds the
                    //reserved nibble + top of Max Adver Int, handled by rsvd/maxAdverInt below.
                    decode: function (this: VRRP): void {
                        const version: number = this.instance.version.getValue(0)
                        if (version !== 2) return
                        this.instance.authType.setValue(BufferToUInt8(this.readBytes(4, 1)))
                    },
                    encode: function (this: VRRP): void {
                        const version: number = this.instance.version.getValue(2)
                        if (version !== 2) return
                        const authType: number = this.instance.authType.getValue(0)
                        this.instance.authType.setValue(authType)
                        this.writeBytes(4, Buffer.from([authType & 0xFF]))
                    }
                },
                adverInt: {
                    type: 'integer',
                    label: 'Adver Int (seconds)',
                    minimum: 0,
                    maximum: 255,
                    //v2 only: byte 5, advertisement interval in whole seconds (RFC 3768 §5.3.7).
                    decode: function (this: VRRP): void {
                        const version: number = this.instance.version.getValue(0)
                        if (version !== 2) return
                        this.instance.adverInt.setValue(BufferToUInt8(this.readBytes(5, 1)))
                    },
                    encode: function (this: VRRP): void {
                        const version: number = this.instance.version.getValue(2)
                        if (version !== 2) return
                        const adverInt: number = this.instance.adverInt.getValue(1)
                        this.instance.adverInt.setValue(adverInt)
                        this.writeBytes(5, Buffer.from([adverInt & 0xFF]))
                    }
                },
                rsvd: {
                    type: 'integer',
                    label: 'Reserved',
                    minimum: 0,
                    maximum: 15,
                    //v3 only: high 4 bits of byte 4 are reserved (RFC 5798 §5.2.4). Preserved verbatim.
                    decode: function (this: VRRP): void {
                        const version: number = this.instance.version.getValue(0)
                        if (version !== 3) return
                        this.instance.rsvd.setValue(this.readBits(4, 1, 0, 4))
                    },
                    encode: function (this: VRRP): void {
                        const version: number = this.instance.version.getValue(2)
                        if (version !== 3) return
                        const rsvd: number = this.instance.rsvd.getValue(0)
                        this.instance.rsvd.setValue(rsvd)
                        this.writeBits(4, 1, 0, 4, rsvd)
                    }
                },
                maxAdverInt: {
                    type: 'integer',
                    label: 'Max Adver Int (centiseconds)',
                    minimum: 0,
                    maximum: 4095,
                    //v3 only: low 4 bits of byte 4 + all of byte 5 = 12-bit Max Advertisement Interval in
                    //centiseconds (RFC 5798 §5.2.5).
                    decode: function (this: VRRP): void {
                        const version: number = this.instance.version.getValue(0)
                        if (version !== 3) return
                        this.instance.maxAdverInt.setValue(this.readBits(4, 2, 4, 12))
                    },
                    encode: function (this: VRRP): void {
                        const version: number = this.instance.version.getValue(2)
                        if (version !== 3) return
                        const maxAdverInt: number = this.instance.maxAdverInt.getValue(0)
                        this.instance.maxAdverInt.setValue(maxAdverInt)
                        this.writeBits(4, 2, 4, 12, maxAdverInt)
                    }
                },
                reserved45: {
                    type: 'string',
                    label: 'Reserved',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    hidden: true,
                    //Bytes 4-5 for any version other than 2 or 3 (a malformed or future advertisement):
                    //no v2/v3 field owns them, so capture them verbatim here to keep the round-trip
                    //lossless (decode never fails, and each octet is still written by exactly one field).
                    decode: function (this: VRRP): void {
                        const version: number = this.instance.version.getValue(0)
                        if (version === 2 || version === 3) return
                        this.instance.reserved45.setValue(BufferToHex(this.readBytes(4, 2)))
                    },
                    encode: function (this: VRRP): void {
                        const version: number = this.instance.version.getValue(2)
                        if (version === 2 || version === 3) return
                        if (this.instance.reserved45.isUndefined()) return
                        this.writeBytes(4, HexToBuffer(this.instance.reserved45.getValue('0000')))
                    }
                },
                checksum: {
                    type: 'integer',
                    label: 'Checksum',
                    minimum: 0,
                    maximum: 65535,
                    //Honoured verbatim (faithful executor): decode reads it, encode writes the same value
                    //back untouched. VRRP checksums differ by version (v2 over the message only, v3 over
                    //an IP pseudo-header too), so recomputation is left to the caller.
                    decode: function (this: VRRP): void {
                        this.instance.checksum.setValue(BufferToUInt16(this.readBytes(6, 2)))
                    },
                    encode: function (this: VRRP): void {
                        let checksum: number = this.instance.checksum.getValue(0)
                        checksum = checksum > 65535 ? 65535 : checksum
                        checksum = checksum < 0 ? 0 : checksum
                        this.instance.checksum.setValue(checksum)
                        this.writeBytes(6, UInt16ToBuffer(checksum))
                    }
                },
                addresses: {
                    type: 'array',
                    label: 'IP Addresses',
                    items: {
                        type: 'string',
                        label: 'IP Address',
                        minLength: 7,
                        maxLength: 15,
                        contentEncoding: StringContentEncodingEnum.IPv4
                    },
                    //Count IPvX addresses follow the fixed 8-byte header. For IPv4-carried VRRP each
                    //address is 4 bytes; IPv6-carried v3 (16-byte addresses) is not modelled here.
                    decode: function (this: VRRP): void {
                        const count: number = this.instance.count.getValue(0)
                        const addresses: string[] = []
                        const available: number = this.#available()
                        for (let i: number = 0; i < count; i++) {
                            if (8 + i * 4 + 4 > available) break
                            addresses.push(BufferToIPv4(this.readBytes(8 + i * 4, 4)))
                        }
                        this.instance.addresses.setValue(addresses)
                    },
                    encode: function (this: VRRP): void {
                        const addresses: string[] | undefined = this.instance.addresses.getValue()
                        if (!addresses) return
                        addresses.forEach((address: string, i: number): void => {
                            this.writeBytes(8 + i * 4, IPv4ToBuffer(address))
                        })
                    }
                },
                authData: {
                    type: 'string',
                    label: 'Authentication Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    //v2 with Auth Type 1 (Simple Text Password, RFC 2338/3768): 8 trailing bytes of
                    //authentication data after the address list. Kept as hex, re-emitted verbatim.
                    decode: function (this: VRRP): void {
                        const version: number = this.instance.version.getValue(0)
                        const authType: number = this.instance.authType.getValue(0)
                        if (version !== 2 || authType !== 1) return
                        const count: number = this.instance.count.getValue(0)
                        //Bounded by the IP payload (mirrors the address loop) so a truncated auth packet
                        //does not pull trailing L2 padding into the authentication field.
                        if (8 + count * 4 + 8 > this.#available()) return
                        this.instance.authData.setValue(BufferToHex(this.readBytes(8 + count * 4, 8)))
                    },
                    encode: function (this: VRRP): void {
                        const version: number = this.instance.version.getValue(2)
                        const authType: number = this.instance.authType.getValue(0)
                        if (version !== 2 || authType !== 1) return
                        if (this.instance.authData.isUndefined()) return
                        const count: number = this.instance.count.getValue(0)
                        this.writeBytes(8 + count * 4, HexToBuffer(this.instance.authData.getValue('')))
                    }
                }
            }
        }
    }

    public readonly id: string = 'vrrp'

    public readonly matchKeys: string[] = ['ipproto:112']

    public readonly name: string = 'Virtual Router Redundancy Protocol'

    public readonly nickname: string = 'VRRP'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        const protocol: number = this.prevCodecModule.instance.protocol.getValue(0)
        const nxt: number = this.prevCodecModule.instance.nxt.getValue(0)
        if (protocol !== 112 && nxt !== 112) return false
        return this.#available() >= 8
    }

    //A leaf header — nothing rides on top of a VRRP advertisement.
    public readonly demuxProducers: DemuxProducer[] = []

}
