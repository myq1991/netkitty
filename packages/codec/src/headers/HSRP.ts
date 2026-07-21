import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {UInt8ToBuffer} from '../helper/NumberToBuffer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToIPv4} from '../helper/BufferToIP'
import {IPv4ToBuffer} from '../helper/IPToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * HSRP — Hot Standby Router Protocol version 1 (RFC 2281, Cisco), carried over UDP port 1985 to the
 * all-routers multicast group 224.0.0.2. The version-1 message is a fixed 20 bytes: Version (0 for v1),
 * Op Code (0 Hello / 1 Coup / 2 Resign), State (0 Initial / 1 Learn / 2 Listen / 4 Speak / 8 Standby /
 * 16 Active), Hellotime and Holdtime (seconds), Priority, Group, a Reserved byte, an 8-byte
 * Authentication Data field (a plaintext password, default "cisco" — kept verbatim as hex so any value
 * round-trips), and the 4-byte Virtual IP Address.
 *
 * Only version 0 (HSRPv1) is decoded field-by-field; a non-zero Version (HSRPv2 uses a different,
 * TLV-based layout on this port) falls back to a verbatim `rawBody` hex so the message still round-trips
 * byte-for-byte. HSRP is a leaf — nothing rides on top of it. The message is bounded by the 20-byte v1
 * mandatory section; any trailing bytes in the UDP datagram are left to the codec's recursion / RawData.
 */
export class HSRP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (HSRP.#schemaCache ??= HSRP.#buildSchema())
    }

    /** The payload length bounded by the UDP datagram (so retained ethernet padding/FCS is not absorbed). */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /**
     * A single-octet unsigned field of the v1 mandatory section at `offset`, decoded/encoded only when
     * Version is 0 (HSRPv1). No `enum` constraint: encode is a faithful executor that must be able to
     * craft any Op Code / State value (including illegal ones), so the field stays a plain [0, 255]
     * integer. Encode clamps to that range (recording an error, never throwing) — byte-for-byte
     * identical to a hand-written uint8 for in-range values.
     */
    static #v1Uint8(name: string, offset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 255,
            decode: function (this: HSRP): void {
                if (this.instance.version.getValue(0) !== 0) return
                (this.instance as any)[name].setValue(this.readBytes(offset, 1)[0])
            },
            encode: function (this: HSRP): void {
                if (this.instance.version.getValue(0) !== 0) return
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > 255) {
                    this.recordError(node.getPath(), 'Maximum value is 255')
                    value = 255
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(offset, UInt8ToBuffer(value))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'HSRP op=${opCode} state=${state} group=${group}',
            properties: {
                //Version — 0 for HSRPv1. Always decoded; it selects the v1 field layout vs the rawBody
                //fallback (a non-zero version is HSRPv2, which uses a different TLV layout on this port).
                version: this.fieldUInt('version', 0, 1, 'Version'),
                //Op Code: 0 Hello, 1 Coup, 2 Resign.
                opCode: this.#v1Uint8('opCode', 1, 'Op Code'),
                //State: 0 Initial, 1 Learn, 2 Listen, 4 Speak, 8 Standby, 16 Active.
                state: this.#v1Uint8('state', 2, 'State'),
                helloTime: this.#v1Uint8('helloTime', 3, 'Hellotime'),
                holdTime: this.#v1Uint8('holdTime', 4, 'Holdtime'),
                priority: this.#v1Uint8('priority', 5, 'Priority'),
                group: this.#v1Uint8('group', 6, 'Group'),
                //Reserved byte — kept verbatim and re-emitted so a non-canonical frame stays byte-perfect.
                reserved: this.#v1Uint8('reserved', 7, 'Reserved'),
                //Authentication Data (8 bytes) — a plaintext password (default "cisco", NUL-padded). Kept
                //verbatim as hex so any value (or binary garbage) round-trips byte-for-byte.
                authData: {
                    type: 'string',
                    label: 'Authentication Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: HSRP): void {
                        if (this.instance.version.getValue(0) !== 0) return
                        this.instance.authData.setValue(BufferToHex(this.readBytes(8, 8)))
                    },
                    encode: function (this: HSRP): void {
                        if (this.instance.version.getValue(0) !== 0) return
                        this.writeBytes(8, HexToBuffer(this.instance.authData.getValue('0000000000000000')))
                    }
                },
                //Virtual IP Address — the group's shared gateway address.
                virtualIP: {
                    type: 'string',
                    label: 'Virtual IP Address',
                    minLength: 7,
                    maxLength: 15,
                    contentEncoding: StringContentEncodingEnum.IPv4,
                    decode: function (this: HSRP): void {
                        if (this.instance.version.getValue(0) !== 0) return
                        this.instance.virtualIP.setValue(BufferToIPv4(this.readBytes(16, 4)))
                    },
                    encode: function (this: HSRP): void {
                        if (this.instance.version.getValue(0) !== 0) return
                        const value: string = this.instance.virtualIP.getValue('0.0.0.0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        this.instance.virtualIP.setValue(value)
                        this.writeBytes(16, IPv4ToBuffer(value))
                    }
                },
                //Raw-body fallback for a non-zero Version (HSRPv2, different layout). Kept verbatim from
                //just after the Version byte to the end of the UDP payload, byte-perfect.
                rawBody: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: HSRP): void {
                        if (this.instance.version.getValue(0) === 0) return
                        const end: number = this.#payloadLength()
                        if (end <= 1) return
                        this.instance.rawBody.setValue(BufferToHex(this.readBytes(1, end - 1)))
                    },
                    encode: function (this: HSRP): void {
                        if (this.instance.version.getValue(0) === 0) return
                        if (this.instance.rawBody.isUndefined()) return
                        this.writeBytes(1, HexToBuffer(this.instance.rawBody.getValue('')))
                    }
                }
            }
        }
    }

    public readonly id: string = 'hsrp'

    public readonly name: string = 'Hot Standby Router Protocol'

    public readonly nickname: string = 'HSRP'

    public readonly matchKeys: string[] = ['udpport:1985']

    public match(): boolean {
        //HSRP rides on UDP port 1985. Require the full 20-byte v1 mandatory section within the UDP
        //payload (bounded by the datagram length, not the frame, so ethernet padding is not miscounted);
        //a shorter datagram is not an HSRP message and falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        return this.#payloadLength() >= 20
    }

    //A leaf header — nothing is carried on top of an HSRP message.
    public readonly demuxProducers: DemuxProducer[] = []

}
