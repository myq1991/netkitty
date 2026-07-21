import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * NHRP — NBMA Next Hop Resolution Protocol (RFC 2332), carried directly over IP as protocol 54. Every
 * NHRP packet opens with a 20-byte Fixed Header — ar$afn (Address Family Number of the NBMA network),
 * ar$pro.type + ar$pro.snap (the protocol whose next hop is being resolved, an EtherType plus an
 * optional SNAP), ar$hopcnt, ar$pktsz (the total NHRP packet length), ar$chksum (an IP-style
 * ones-complement checksum over the whole NHRP packet), ar$extoff (offset to the first extension), the
 * op.version / op.type opcode (1 Resolution Request, 2 Resolution Reply, 3 Registration Request,
 * 4 Registration Reply, 5 Purge Request, 6 Purge Reply, 7 Error Indication), and ar$shtl / ar$sstl
 * (the source NBMA address / subaddress type+length) — followed by the type-specific Mandatory Part and
 * any Extensions.
 *
 * The Mandatory Part and Extensions are opcode-dependent, variable-length (their sub-address lengths are
 * driven by ar$shtl and the per-entry CIE type/length octets) and carry cross-field context, so this
 * codec keeps them verbatim as `body` hex (byte-perfect) and does not sub-decode them. Packet Length is
 * auto-computed from the body on encode when not supplied, else honored verbatim (a crafted packet may
 * lie); the checksum is honored verbatim, never recomputed (encode is a faithful executor). The body is
 * bounded by both Packet Length and the enclosing IP payload, so trailing bytes are left to the codec's
 * recursion / RawData. A well-formed packet round-trips byte-for-byte.
 */
export class NHRP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (NHRP.#schemaCache ??= NHRP.#buildSchema())
    }

    /**
     * Bytes of NHRP the IP layer below says are available. IPv4 carries a total-length field, so the
     * NHRP payload is (total length - IP header length); IPv6 carries the payload length directly (plen).
     * Mirrors the OSPF/GRE pattern so the body decode and the match gate are bounded by the real on-wire
     * length rather than trusting the NHRP Packet Length field alone (which a malformed packet may
     * overstate). Returns 0 when neither is present.
     * @private
     */
    #available(): number {
        const prev: any = this.prevCodecModule
        if (!prev) return 0
        const ipv4TotalLength: number = prev.instance.length.getValue(0)
        if (ipv4TotalLength) return ipv4TotalLength - prev.length
        const ipv6PayloadLength: number = prev.instance.plen.getValue(0)
        if (ipv6PayloadLength) return ipv6PayloadLength
        return 0
    }

    /**
     * Header-relative end offset of the NHRP body: the Packet Length field, clamped down to the bytes the
     * IP layer actually made available (#available). Never less than the 20-byte Fixed Header. Bounds the
     * verbatim body so a corrupt Packet Length can't read past the IP payload.
     * @private
     */
    #bodyEnd(): number {
        let end: number = this.instance.packetSize.getValue(0)
        const available: number = this.#available()
        if (available && available < end) end = available
        if (end < 20) end = 20
        return end
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'NHRP op=${opType} pktsz=${packetSize}',
            properties: {
                //==== Fixed Header (20 bytes, RFC 2332 §5.2.0.1) ====
                afn: this.fieldUInt('afn', 0, 2, 'Address Family Number'),
                //The protocol being resolved, an EtherType (e.g. 0x0800 IPv4) — kept as a hex string like
                //eth.etherType, byte-perfect and editable.
                protocolType: this.fieldHex('protocolType', 2, 2, 'Protocol Type'),
                protocolSnap: this.fieldHex('protocolSnap', 4, 5, 'Protocol SNAP'),
                hopCount: this.fieldUInt('hopCount', 9, 1, 'Hop Count'),
                packetSize: {
                    type: 'integer',
                    label: 'Packet Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: NHRP): void {
                        this.instance.packetSize.setValue(BufferToUInt16(this.readBytes(10, 2)))
                    },
                    encode: function (this: NHRP): void {
                        //Packet Length counts the whole NHRP packet = 20-byte Fixed Header + body.
                        //Honored when supplied (a crafted packet may lie); else derived from the body.
                        const provided: number | undefined = this.instance.packetSize.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 20 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.packetSize.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        this.instance.packetSize.setValue(value)
                        this.writeBytes(10, UInt16ToBuffer(value))
                    }
                },
                //Honored verbatim: the NHRP checksum (ones-complement over the whole packet) is never
                //recomputed, so a captured packet round-trips byte-for-byte.
                checksum: this.fieldUInt('checksum', 12, 2, 'Checksum'),
                extensionOffset: this.fieldUInt('extensionOffset', 14, 2, 'Extension Offset'),
                opVersion: this.fieldUInt('opVersion', 16, 1, 'Version'),
                opType: this.fieldUInt('opType', 17, 1, 'Operation Type'),
                shtl: this.fieldUInt('shtl', 18, 1, 'Source NBMA Address Type/Length'),
                sstl: this.fieldUInt('sstl', 19, 1, 'Source NBMA Subaddress Type/Length'),
                //The type-specific Mandatory Part + Extensions after the 20-byte Fixed Header, kept
                //verbatim. Bounded by both the Packet Length and the enclosing IP payload (#bodyEnd), so
                //trailing / pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: NHRP): void {
                        const end: number = this.#bodyEnd()
                        this.instance.body.setValue(end > 20 ? BufferToHex(this.readBytes(20, end - 20)) : '')
                    },
                    encode: function (this: NHRP): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(20, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'nhrp'

    public readonly name: string = 'NBMA Next Hop Resolution Protocol'

    public readonly nickname: string = 'NHRP'

    public readonly matchKeys: string[] = ['ipproto:54']

    public match(): boolean {
        if (!this.prevCodecModule) return false
        //NHRP sits directly on IP (protocol 54). Accept the demux value from either the IPv4 protocol
        //field or the IPv6 next-header field, and require at least a full 20-byte Fixed Header of IP
        //payload to be present.
        const protocol: number = this.prevCodecModule.instance.protocol.getValue(0)
        const nextHeader: number = this.prevCodecModule.instance.nxt.getValue(0)
        if (protocol !== 54 && nextHeader !== 54) return false
        return this.#available() >= 20
    }

    //A leaf header — the Mandatory Part / Extensions require opcode-dependent, length-driven parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
