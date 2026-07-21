import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'

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
                poll: this.fieldInt8('poll', 2, 'Poll Interval'),
                precision: this.fieldInt8('precision', 3, 'Precision'),
                rootDelay: this.fieldUInt('rootDelay', 4, 4, 'Root Delay'),
                rootDispersion: this.fieldUInt('rootDispersion', 8, 4, 'Root Dispersion'),
                refId: this.fieldHex('refId', 12, 4, 'Reference ID'),
                refTimestamp: this.fieldHex('refTimestamp', 16, 8, 'Reference Timestamp'),
                originTimestamp: this.fieldHex('originTimestamp', 24, 8, 'Origin Timestamp'),
                receiveTimestamp: this.fieldHex('receiveTimestamp', 32, 8, 'Receive Timestamp'),
                transmitTimestamp: this.fieldHex('transmitTimestamp', 40, 8, 'Transmit Timestamp')
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
