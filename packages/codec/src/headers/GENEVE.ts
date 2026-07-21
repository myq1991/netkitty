import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16} from '../helper/BufferToNumber'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One GENEVE variable-length option (RFC 8926 §3.5). */
type GeneveOption = {optionClass: number, type: number, critical: boolean, reserved: number, data: string}

/**
 * GENEVE — Generic Network Virtualization Encapsulation (RFC 8926), a network-virtualization overlay on
 * UDP port 6081. The 8-byte base header is: Version(2 bits) + Opt Len(6 bits, options length in 4-byte
 * units), O(OAM) + C(Critical) + 6 reserved bits, a 16-bit Protocol Type (the EtherType of the payload:
 * 0x6558 = Transparent Ethernet Bridging, 0x0800 = IPv4, 0x86dd = IPv6), a 24-bit VNI, and a reserved
 * byte. It is followed by Opt Len*4 bytes of variable-length options, then the inner frame.
 *
 * Like VXLAN, this codec decodes only its own header + options (headerLength = 8 + Opt Len*4); the inner
 * frame is left to the codec's recursion. Protocol Type is declared as an `ethertype` demux producer so
 * an inner IPv4/IPv6 packet is dispatched to IPv4/IPv6 (which accept a 'geneve' tunnel parent), while a
 * Transparent-Ethernet-Bridging (0x6558) payload falls through to EthernetII (which already accepts a
 * 'geneve' parent). The whole nested packet round-trips byte-for-byte layer by layer.
 */
export class GENEVE extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (GENEVE.#schemaCache ??= GENEVE.#buildSchema())
    }

    /** The payload length bounded by the UDP datagram (so a retained FCS/padding is not absorbed). */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'GENEVE vni=${vni} proto=${protocolType}',
            properties: {
                version: {
                    type: 'integer', label: 'Version', minimum: 0, maximum: 3,
                    decode: function (this: GENEVE): void { this.instance.version.setValue(this.readBits(0, 1, 0, 2)) },
                    encode: function (this: GENEVE): void { this.writeBits(0, 1, 0, 2, this.instance.version.getValue(0)) }
                },
                //Opt Len (options length in 4-byte units) — metadata; the value is derived from the
                //options list by the `body` master on encode and read from the wire on decode.
                optLen: {type: 'integer', label: 'Option Length', minimum: 0, maximum: 63},
                oam: {
                    type: 'boolean', label: 'OAM',
                    decode: function (this: GENEVE): void { this.instance.oam.setValue(!!this.readBits(1, 1, 0, 1)) },
                    encode: function (this: GENEVE): void {
                        const oam: boolean = !!this.instance.oam.getValue()
                        this.instance.oam.setValue(oam)
                        this.writeBits(1, 1, 0, 1, oam ? 1 : 0)
                    }
                },
                critical: {
                    type: 'boolean', label: 'Critical Options Present',
                    decode: function (this: GENEVE): void { this.instance.critical.setValue(!!this.readBits(1, 1, 1, 1)) },
                    encode: function (this: GENEVE): void {
                        const critical: boolean = !!this.instance.critical.getValue()
                        this.instance.critical.setValue(critical)
                        this.writeBits(1, 1, 1, 1, critical ? 1 : 0)
                    }
                },
                //Reserved 6 bits of byte 1, kept verbatim for a byte-perfect round-trip.
                reserved1: {
                    type: 'integer', label: 'Reserved', minimum: 0, maximum: 63, hidden: true,
                    decode: function (this: GENEVE): void { this.instance.reserved1.setValue(this.readBits(1, 1, 2, 6)) },
                    encode: function (this: GENEVE): void { this.writeBits(1, 1, 2, 6, this.instance.reserved1.getValue(0)) }
                },
                //Protocol Type is the EtherType of the inner frame — stored as a lowercase hex string
                //(like eth.etherType) so it can drive the `ethertype` demux dimension to the inner codec.
                protocolType: {
                    type: 'string', label: 'Protocol Type', contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: GENEVE): void { this.instance.protocolType.setValue(BufferToHex(this.readBytes(2, 2))) },
                    encode: function (this: GENEVE): void {
                        const hex: string = this.instance.protocolType.getValue('6558')
                        this.writeBytes(2, HexToBuffer(hex.padStart(4, '0').slice(-4)))
                    }
                },
                vni: {
                    type: 'integer', label: 'VNI', minimum: 0, maximum: 16777215,
                    decode: function (this: GENEVE): void { this.instance.vni.setValue(this.readBits(4, 3, 0, 24)) },
                    encode: function (this: GENEVE): void {
                        let vni: number = this.instance.vni.getValue(0)
                        if (vni > 16777215) { this.recordError(this.instance.vni.getPath(), 'Maximum value is 16777215'); vni = 16777215 }
                        if (vni < 0) { this.recordError(this.instance.vni.getPath(), 'Minimum value is 0'); vni = 0 }
                        this.instance.vni.setValue(vni)
                        this.writeBits(4, 3, 0, 24, vni)
                    }
                },
                //Reserved byte 7, kept verbatim.
                reserved2: {
                    type: 'string', label: 'Reserved', contentEncoding: StringContentEncodingEnum.HEX, hidden: true,
                    decode: function (this: GENEVE): void { this.instance.reserved2.setValue(BufferToHex(this.readBytes(7, 1))) },
                    encode: function (this: GENEVE): void { this.writeBytes(7, HexToBuffer(this.instance.reserved2.getValue('00'))) }
                },
                options: {
                    type: 'array', label: 'Options',
                    items: {
                        type: 'object', label: 'Option',
                        properties: {
                            optionClass: {type: 'integer', label: 'Option Class', minimum: 0, maximum: 65535},
                            type: {type: 'integer', label: 'Type', minimum: 0, maximum: 255},
                            critical: {type: 'boolean', label: 'Critical'},
                            reserved: {type: 'integer', label: 'Reserved', minimum: 0, maximum: 7, hidden: true},
                            data: {type: 'string', label: 'Data', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    }
                },
                //Any bytes in the option region the option walk could not structure (malformed) are kept
                //verbatim so the header always round-trips and the inner frame starts at the right offset.
                optionsTail: {type: 'string', label: 'Options Tail', contentEncoding: StringContentEncodingEnum.HEX, hidden: true},
                //Master field: parses/emits the Opt Len field and the option region (runs after the fixed
                //header fields — property order — so the fixed bytes are already read/written).
                body: {
                    type: 'string', label: 'Body', contentEncoding: StringContentEncodingEnum.HEX, hidden: true,
                    decode: function (this: GENEVE): void {
                        const available: number = this.#available()
                        const optLen: number = this.readBits(0, 1, 2, 6)
                        this.instance.optLen.setValue(optLen)
                        const end: number = Math.min(8 + optLen * 4, available)
                        let offset: number = 8
                        const options: GeneveOption[] = []
                        while (offset + 4 <= end) {
                            const optionClass: number = BufferToUInt16(this.readBytes(offset, 2))
                            const type: number = BufferToUInt8(this.readBytes(offset + 2, 1))
                            const b3: number = BufferToUInt8(this.readBytes(offset + 3, 1))
                            const reserved: number = (b3 >> 5) & 0x07
                            const dataBytes: number = (b3 & 0x1f) * 4
                            if (offset + 4 + dataBytes > end) break
                            options.push({
                                optionClass: optionClass,
                                type: type,
                                critical: !!(type & 0x80),
                                reserved: reserved,
                                data: dataBytes > 0 ? BufferToHex(this.readBytes(offset + 4, dataBytes)) : ''
                            })
                            offset += 4 + dataBytes
                        }
                        this.instance.options.setValue(options)
                        //Consume the rest of the (optLen-defined) option region verbatim so headerLength
                        //= 8 + optLen*4 and the inner frame is dispatched at the right offset.
                        this.instance.optionsTail.setValue(offset < end ? BufferToHex(this.readBytes(offset, end - offset)) : '')
                    },
                    encode: function (this: GENEVE): void {
                        let offset: number = 8
                        const options: GeneveOption[] = this.instance.options.getValue([])
                        if (options) for (let i: number = 0; i < options.length; i++) {
                            const option: GeneveOption = options[i]
                            const data: Buffer = HexToBuffer(option.data ? option.data : '')
                            //Option data is a 5-bit length in 4-byte units, so it must be a multiple of 4
                            //bytes and at most 124 — record rather than silently wrap a malformed length.
                            if (data.length % 4 !== 0 || data.length > 124) this.recordError(this.instance.options.getPath() + `[${i}].data`, 'Option data must be a multiple of 4 bytes and at most 124')
                            this.writeBytes(offset, UInt16ToBuffer(option.optionClass ? option.optionClass : 0)); offset += 2
                            this.writeBytes(offset, Buffer.from([(option.type ? option.type : 0) & 0xff])); offset += 1
                            const reserved: number = (option.reserved ? option.reserved : 0) & 0x07
                            this.writeBytes(offset, Buffer.from([(reserved << 5) | ((data.length / 4) & 0x1f)])); offset += 1
                            if (data.length) { this.writeBytes(offset, data); offset += data.length }
                        }
                        const tail: Buffer = HexToBuffer(this.instance.optionsTail.getValue(''))
                        if (tail.length) { this.writeBytes(offset, tail); offset += tail.length }
                        //Opt Len = the whole option region in 4-byte units.
                        this.writeBits(0, 1, 2, 6, ((offset - 8) / 4) & 0x3f)
                        this.instance.optLen.setValue((offset - 8) / 4)
                    }
                }
            }
        }
    }

    public readonly id: string = 'geneve'

    public readonly name: string = 'Generic Network Virtualization Encapsulation'

    public readonly nickname: string = 'GENEVE'

    public readonly matchKeys: string[] = ['udpport:6081']

    public match(): boolean {
        //Require the 8-byte base header within the UDP payload (see RADIUS: bound by payload).
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp' && this.#available() >= 8
    }

    //Protocol Type is an EtherType; declaring it in the 'ethertype' namespace dispatches the inner IPv4/
    //IPv6 packet to the O(1) bucket (which accepts a 'geneve' parent), while a 0x6558 Ethernet payload
    //falls through to EthernetII's tunnel-aware match.
    public readonly demuxProducers: DemuxProducer[] = [{field: 'protocolType', namespace: 'ethertype', kind: 'string'}]

}
