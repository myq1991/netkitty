import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BufferToInt8} from '../../helper/BufferToNumber'
import {Int8ToBuffer} from '../../helper/NumberToBuffer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * NTP — Network Time Protocol (RFC 5905), the 48-byte packet header. Rides UDP port 123. Fields per
 * RFC 5905 §7.3: a flags byte (LI/VN/Mode), Stratum, Poll and Precision (signed power-of-two seconds),
 * Root Delay/Dispersion (NTP short 16.16 fixed-point, kept as raw uint32), Reference Identifier, and
 * four 64-bit NTP timestamps (Reference/Origin/Receive/Transmit). Extension fields and the optional
 * MAC (authenticated NTP) fall to the following raw layer.
 */
export class NTP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (NTP.#schemaCache ??= NTP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            properties: {
                //Byte 0 packs three bit fields (bit 0 = MSB): LI[0..1], VN[2..4], Mode[5..7].
                li: {
                    type: 'integer',
                    label: 'Leap Indicator',
                    minimum: 0,
                    maximum: 3,
                    decode: function (this: NTP): void { this.instance.li.setValue(this.readBits(0, 1, 0, 2)) },
                    encode: function (this: NTP): void { this.writeBits(0, 1, 0, 2, this.instance.li.getValue(0)) }
                },
                vn: {
                    type: 'integer',
                    label: 'Version',
                    minimum: 0,
                    maximum: 7,
                    decode: function (this: NTP): void { this.instance.vn.setValue(this.readBits(0, 1, 2, 3)) },
                    encode: function (this: NTP): void { this.writeBits(0, 1, 2, 3, this.instance.vn.getValue(0)) }
                },
                mode: {
                    type: 'integer',
                    label: 'Mode',
                    minimum: 0,
                    maximum: 7,
                    decode: function (this: NTP): void { this.instance.mode.setValue(this.readBits(0, 1, 5, 3)) },
                    encode: function (this: NTP): void { this.writeBits(0, 1, 5, 3, this.instance.mode.getValue(0)) }
                },
                stratum: this.fieldUInt('stratum', 1, 1, 'Stratum'),
                //Poll and Precision are signed power-of-two-second exponents (RFC 5905 §7.3).
                poll: {
                    type: 'integer',
                    label: 'Poll Interval',
                    minimum: -128,
                    maximum: 127,
                    decode: function (this: NTP): void { this.instance.poll.setValue(BufferToInt8(this.readBytes(2, 1))) },
                    encode: function (this: NTP): void { this.writeBytes(2, Int8ToBuffer(this.instance.poll.getValue(0))) }
                },
                precision: {
                    type: 'integer',
                    label: 'Precision',
                    minimum: -128,
                    maximum: 127,
                    decode: function (this: NTP): void { this.instance.precision.setValue(BufferToInt8(this.readBytes(3, 1))) },
                    encode: function (this: NTP): void { this.writeBytes(3, Int8ToBuffer(this.instance.precision.getValue(0))) }
                },
                rootDelay: this.fieldUInt('rootDelay', 4, 4, 'Root Delay'),
                rootDispersion: this.fieldUInt('rootDispersion', 8, 4, 'Root Dispersion'),
                refId: {
                    type: 'string',
                    label: 'Reference ID',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: NTP): void { this.instance.refId.setValue(BufferToHex(this.readBytes(12, 4))) },
                    encode: function (this: NTP): void { this.writeBytes(12, HexToBuffer(this.instance.refId.getValue('00000000'))) }
                },
                refTimestamp: {
                    type: 'string',
                    label: 'Reference Timestamp',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: NTP): void { this.instance.refTimestamp.setValue(BufferToHex(this.readBytes(16, 8))) },
                    encode: function (this: NTP): void { this.writeBytes(16, HexToBuffer(this.instance.refTimestamp.getValue('0000000000000000'))) }
                },
                originTimestamp: {
                    type: 'string',
                    label: 'Origin Timestamp',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: NTP): void { this.instance.originTimestamp.setValue(BufferToHex(this.readBytes(24, 8))) },
                    encode: function (this: NTP): void { this.writeBytes(24, HexToBuffer(this.instance.originTimestamp.getValue('0000000000000000'))) }
                },
                receiveTimestamp: {
                    type: 'string',
                    label: 'Receive Timestamp',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: NTP): void { this.instance.receiveTimestamp.setValue(BufferToHex(this.readBytes(32, 8))) },
                    encode: function (this: NTP): void { this.writeBytes(32, HexToBuffer(this.instance.receiveTimestamp.getValue('0000000000000000'))) }
                },
                transmitTimestamp: {
                    type: 'string',
                    label: 'Transmit Timestamp',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: NTP): void { this.instance.transmitTimestamp.setValue(BufferToHex(this.readBytes(40, 8))) },
                    encode: function (this: NTP): void { this.writeBytes(40, HexToBuffer(this.instance.transmitTimestamp.getValue('0000000000000000'))) }
                }
            }
        }
    }

    public readonly id: string = 'ntp'

    public readonly name: string = 'Network Time Protocol'

    public readonly nickname: string = 'NTP'

    //Port-defined (udp:123). No reliable content signature, so it is a plain bucket entry (no
    //heuristicFallback): it is NTP only when it rides udp:123.
    public readonly matchKeys: string[] = ['udpport:123']

    public match(): boolean {
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp'
    }

}
