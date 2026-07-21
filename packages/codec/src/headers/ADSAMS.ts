import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Beckhoff ADS/AMS (Automation Device Specification / Automation Message Specification, TwinCAT), TCP
 * port 48898 (0xBF02). An ADS/AMS packet begins with a 6-byte AMS/TCP header — a 2-byte Reserved field
 * (0 for an AMS command) and a 4-byte Length (the count of the bytes that follow the AMS/TCP header, i.e.
 * the 32-byte AMS header plus its data) — followed by the 32-byte AMS header: the target AmsNetId (6) and
 * target AmsPort (2), the source AmsNetId (6) and source AmsPort (2), the Command Id (2), State Flags (2),
 * Data Length (4), Error Code (4) and Invoke Id (4), then `Data Length` bytes of command-specific data.
 *
 * ⚠️ Every multi-byte field is LITTLE-ENDIAN (ADS/AMS on-wire byte order). There is no little-endian
 * helper in this codebase, so the uint16 / uint32 fields are read and written byte-by-byte in their
 * closures. The 6-byte AmsNetId fields (`a.b.c.d.e.f`) are kept verbatim as hex.
 *
 * The command-specific data is command- and direction-dependent (a Read request carries index group /
 * index offset / length; a Read response carries a result + data; only the paired transaction reveals
 * which), which is cross-packet state, so this single-packet codec keeps it verbatim as `data` hex
 * (byte-perfect) and does not sub-decode it. The AMS/TCP Length is auto-computed from the AMS header +
 * data on encode when not supplied, else honored verbatim (a crafted packet may lie); the data is bounded
 * by Data Length so a pipelined / trailing packet is left to the codec's recursion / RawData. A
 * well-formed packet round-trips byte-for-byte.
 */
export class ADSAMS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (ADSAMS.#schemaCache ??= ADSAMS.#buildSchema())
    }

    /** A little-endian unsigned 16-bit field of 2 octets at `offset`. */
    static #fieldUInt16LE(name: string, offset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 65535,
            decode: function (this: ADSAMS): void {
                const b: Buffer = this.readBytes(offset, 2)
                ;(this.instance as any)[name].setValue(b[0] | (b[1] << 8))
            },
            encode: function (this: ADSAMS): void {
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > 65535) {
                    this.recordError(node.getPath(), 'Maximum value is 65535')
                    value = 65535
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(offset, Buffer.from([value & 0xff, (value >> 8) & 0xff]))
            }
        }
    }

    /** A little-endian unsigned 32-bit field of 4 octets at `offset`. */
    static #fieldUInt32LE(name: string, offset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 4294967295,
            decode: function (this: ADSAMS): void {
                const b: Buffer = this.readBytes(offset, 4)
                //`|` yields a signed int32, so apply `>>> 0` to the WHOLE expression to get an unsigned
                //32-bit value — otherwise a value with the high bit set decodes as a negative number.
                ;(this.instance as any)[name].setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
            },
            encode: function (this: ADSAMS): void {
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > 4294967295) {
                    this.recordError(node.getPath(), 'Maximum value is 4294967295')
                    value = 4294967295
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(offset, Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff]))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'ADS/AMS cmd=${commandId} invoke=${invokeId}',
            properties: {
                //===== AMS/TCP header (6 bytes) =====
                //Reserved: 0 for an AMS command; kept verbatim so any non-zero reserved still round-trips.
                reserved: this.fieldHex('reserved', 0, 2, 'Reserved'),
                length: {
                    type: 'integer',
                    label: 'AMS/TCP Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: ADSAMS): void {
                        const b: Buffer = this.readBytes(2, 4)
                        this.instance.length.setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
                    },
                    encode: function (this: ADSAMS): void {
                        //Length counts the AMS header (32) + the command data that follow the 6-byte
                        //AMS/TCP header. Honored when supplied (a crafted packet may lie); else derived.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 32 + HexToBuffer(this.instance.data.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(2, Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff]))
                    }
                },
                //===== AMS header (32 bytes) =====
                //6-byte AmsNetId values kept verbatim as hex (on-wire order, e.g. c0a800010101).
                targetNetId: this.fieldHex('targetNetId', 6, 6, 'Target AmsNetId'),
                targetPort: this.#fieldUInt16LE('targetPort', 12, 'Target AmsPort'),
                sourceNetId: this.fieldHex('sourceNetId', 14, 6, 'Source AmsNetId'),
                sourcePort: this.#fieldUInt16LE('sourcePort', 20, 'Source AmsPort'),
                //Command Id: 1 ReadDeviceInfo, 2 Read, 3 Write, 4 ReadState, ... (kept as a raw uint, no
                //enum constraint, so any on-wire command id decodes and re-encodes).
                commandId: this.#fieldUInt16LE('commandId', 22, 'Command Id'),
                //State Flags: bit0 response(1)/request(0), bit2 ADS command (0x0004); kept verbatim.
                stateFlags: this.#fieldUInt16LE('stateFlags', 24, 'State Flags'),
                dataLength: {
                    type: 'integer',
                    label: 'Data Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: ADSAMS): void {
                        const b: Buffer = this.readBytes(26, 4)
                        this.instance.dataLength.setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
                    },
                    encode: function (this: ADSAMS): void {
                        //Data Length counts the command data that follow the 38-byte header. Honored when
                        //supplied (a crafted packet may lie); else derived from the data.
                        const provided: number | undefined = this.instance.dataLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.data.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.dataLength.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.dataLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.dataLength.setValue(value)
                        this.writeBytes(26, Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff]))
                    }
                },
                //Error Code honored verbatim (never recomputed).
                errorCode: this.#fieldUInt32LE('errorCode', 30, 'Error Code'),
                invokeId: this.#fieldUInt32LE('invokeId', 34, 'Invoke Id'),
                //The command-specific data after the 38-byte AMS/TCP+AMS header, kept verbatim. Bounded by
                //Data Length (data ends at offset 38 + dataLength) and the captured bytes, so trailing /
                //pipelined data is left to the codec's recursion / RawData.
                data: {
                    type: 'string',
                    label: 'Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: ADSAMS): void {
                        const remaining: number = this.packet.length - this.startPos
                        const dataLength: number = this.instance.dataLength.getValue(0)
                        let end: number = 38 + dataLength
                        if (end > remaining) end = remaining
                        this.instance.data.setValue(end > 38 ? BufferToHex(this.readBytes(38, end - 38)) : '')
                    },
                    encode: function (this: ADSAMS): void {
                        const data: string = this.instance.data.getValue('')
                        if (data) this.writeBytes(38, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 'adsams'

    public readonly name: string = 'Beckhoff ADS/AMS'

    public readonly nickname: string = 'ADS/AMS'

    public readonly matchKeys: string[] = ['tcpport:48898']

    public match(): boolean {
        //ADS/AMS rides on TCP port 48898. The AMS/TCP + AMS headers carry no strong content magic, so
        //the well-known port is the signature: require the full 6-byte AMS/TCP header + 32-byte AMS
        //header (38 bytes) to be present so the fixed AMS-header fields are never re-emitted from a
        //truncated slice.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        return this.packet.length - this.startPos >= 38
    }

    //A leaf header — the command data requires command- and direction-dependent, cross-packet parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
