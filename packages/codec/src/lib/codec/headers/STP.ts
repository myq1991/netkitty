import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16, BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer, UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * STP — Spanning Tree Protocol BPDU (IEEE 802.1D, and RSTP/MSTP 802.1w/s), carried in an 802.3 frame
 * over LLC with DSAP/SSAP 0x42. Every BPDU opens with a 4-byte fixed part: a 2-byte Protocol Identifier
 * (0x0000), a 1-byte Protocol Version (0 STP, 2 RSTP, 3 MSTP) and a 1-byte BPDU Type (0x00 Configuration,
 * 0x02 RST/MST, 0x80 Topology Change Notification).
 *
 * A Configuration / RST BPDU (type 0x00 / 0x02) then carries the full spanning-tree state — Flags, Root
 * Identifier, Root Path Cost, Bridge Identifier, Port Identifier and the four timers (Message Age, Max
 * Age, Hello Time, Forward Delay) — plus, for RST/MST, a trailing remainder (Version 1 Length + any MST
 * extension) kept verbatim as `extra` hex. A TCN BPDU (type 0x80) is just the 4-byte fixed part. The
 * body fields are decoded/encoded only for Configuration/RST types, so a TCN BPDU round-trips as exactly
 * 4 bytes. A well-formed BPDU round-trips byte-for-byte; trailing 802.3 padding falls to RawData.
 */
export class STP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (STP.#schemaCache ??= STP.#buildSchema())
    }

    /** Configuration (0x00) and RST/MST (0x02) BPDUs carry the full body; TCN (0x80) does not. */
    #isConfig(): boolean {
        const type: number = this.instance.bpduType.getValue(0)
        return type === 0x00 || type === 0x02
    }

    /** A body field present only on Configuration/RST BPDUs — read/written verbatim, skipped for TCN. */
    static #bodyUInt(name: string, offset: number, byteLength: number, label: string): ProtocolFieldJSONSchema {
        const max: number = byteLength === 1 ? 255 : byteLength === 2 ? 65535 : 4294967295
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: max,
            decode: function (this: STP): void {
                if (!this.#isConfig()) return
                const buffer: Buffer = this.readBytes(offset, byteLength)
                const value: number = byteLength === 1 ? BufferToUInt8(buffer) : byteLength === 2 ? BufferToUInt16(buffer) : BufferToUInt32(buffer)
                ;(this.instance as any)[name].setValue(value)
            },
            encode: function (this: STP): void {
                if (!this.#isConfig()) return
                let value: number = (this.instance as any)[name].getValue(0)
                if (value > max) value = max
                if (value < 0) value = 0
                const buffer: Buffer = byteLength === 1 ? UInt8ToBuffer(value) : byteLength === 2 ? UInt16ToBuffer(value) : UInt32ToBuffer(value)
                this.writeBytes(offset, buffer)
            }
        }
    }

    /** A verbatim-hex body field present only on Configuration/RST BPDUs (identifiers). */
    static #bodyHex(name: string, offset: number, byteLength: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'string',
            label: label,
            contentEncoding: StringContentEncodingEnum.HEX,
            decode: function (this: STP): void {
                if (!this.#isConfig()) return
                ;(this.instance as any)[name].setValue(BufferToHex(this.readBytes(offset, byteLength)))
            },
            encode: function (this: STP): void {
                if (!this.#isConfig()) return
                const value: string = (this.instance as any)[name].getValue('')
                if (value) this.writeBytes(offset, HexToBuffer(value))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'STP type=${bpduType} version=${protocolVersion}',
            properties: {
                //Fixed 4-byte part, present on every BPDU.
                protocolIdentifier: this.fieldHex('protocolIdentifier', 0, 2, 'Protocol Identifier'),
                protocolVersion: this.fieldUInt('protocolVersion', 2, 1, 'Protocol Version'),
                bpduType: this.fieldUInt('bpduType', 3, 1, 'BPDU Type'),
                //Configuration / RST body (skipped for a 4-byte TCN BPDU).
                flags: this.#bodyUInt('flags', 4, 1, 'Flags'),
                rootIdentifier: this.#bodyHex('rootIdentifier', 5, 8, 'Root Identifier'),
                rootPathCost: this.#bodyUInt('rootPathCost', 13, 4, 'Root Path Cost'),
                bridgeIdentifier: this.#bodyHex('bridgeIdentifier', 17, 8, 'Bridge Identifier'),
                portIdentifier: this.#bodyUInt('portIdentifier', 25, 2, 'Port Identifier'),
                messageAge: this.#bodyUInt('messageAge', 27, 2, 'Message Age'),
                maxAge: this.#bodyUInt('maxAge', 29, 2, 'Max Age'),
                helloTime: this.#bodyUInt('helloTime', 31, 2, 'Hello Time'),
                forwardDelay: this.#bodyUInt('forwardDelay', 33, 2, 'Forward Delay'),
                //RST/MST trailing remainder (Version 1 Length + any MST configuration), kept verbatim.
                //Only an RST/MST BPDU (type 0x02) carries it; a Configuration BPDU (0x00) is exactly 35
                //bytes, so its trailing 802.3 minimum-frame padding is left to RawData rather than absorbed
                //here (which would break the padding's own byte-perfect identity and mislabel it).
                extra: {
                    type: 'string',
                    label: 'Extra',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: STP): void {
                        const bpduType: number = this.instance.bpduType.getValue(0)
                        if (bpduType !== 0x02) return
                        const available: number = this.packet.length - this.startPos
                        if (available > 35) this.instance.extra.setValue(BufferToHex(this.readBytes(35, available - 35)))
                        else this.instance.extra.setValue('')
                    },
                    encode: function (this: STP): void {
                        const bpduType: number = this.instance.bpduType.getValue(0)
                        if (bpduType !== 0x02) return
                        const extra: string = this.instance.extra.getValue('')
                        if (extra) this.writeBytes(35, HexToBuffer(extra))
                    }
                }
            }
        }
    }

    public readonly id: string = 'stp'

    public readonly name: string = 'Spanning Tree Protocol'

    public readonly nickname: string = 'STP'

    public readonly matchKeys: string[] = ['llcsap:66']

    public match(): boolean {
        //An LLC child selected by DSAP 0x42 (66). Confirm the parent is LLC and the DSAP byte is 0x42, and
        //require the 4-byte fixed BPDU part.
        const prev: any = this.prevCodecModule
        if (!prev || prev.id !== 'llc') return false
        if (prev.instance.dsap.getValue(0) !== 0x42) return false
        return this.packet.length - this.startPos >= 4
    }

    //A leaf — a BPDU carries no encapsulated protocol.
    public readonly demuxProducers: DemuxProducer[] = []

}
