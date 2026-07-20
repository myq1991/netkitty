import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * SLMP — SeamLess Message Protocol (Mitsubishi Electric MELSEC / iQ-R, "SLMP"), the open industrial
 * protocol that carries MELSEC device read/write and control requests, commonly on TCP & UDP port 5007.
 * This codec models the ubiquitous 3E-frame BINARY encoding. Every 3E request begins with the subheader
 * 0x5000 (wire bytes `50 00`) and every response with 0xD000 (`D0 00`), followed by a small routing
 * header — Network number, Station (PC) number, request-destination Module I/O number, Multidrop station
 * number — then a Request Data Length that counts every byte AFTER it, and finally the command payload
 * (for a request: Monitor Timer + Command + Subcommand + device specification; for a response: End Code +
 * response data).
 *
 * ⚠️ Except for the 2-byte subheader marker (kept in wire order as `50 00` / `D0 00`, i.e. big-endian
 * 0x5000 / 0xD000), every multi-byte field in the 3E binary frame is LITTLE-ENDIAN. There is no
 * little-endian helper in this codebase, so the uint16 fields are read/written byte-by-byte in their
 * closures.
 *
 * Byte-perfect strategy (minimal slice, per the SLMP layout being command-dependent): structure the
 * subheader + routing header + Request Data Length, and keep the command-specific remainder (Monitor
 * Timer / Command / Subcommand / device data on a request; End Code / data on a response) verbatim as
 * `data` hex. The remainder is bounded by the Request Data Length (data ends at offset 9 + length) and
 * the captured bytes, so a trailing / pipelined message is left to the codec's recursion / RawData. The
 * Request Data Length is auto-computed from the data on encode when not supplied, else honored verbatim
 * (a crafted frame may carry any length). A well-formed message round-trips byte-for-byte.
 */
export class SLMP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SLMP.#schemaCache ??= SLMP.#buildSchema())
    }

    /** A little-endian unsigned 16-bit field of 2 octets at `offset`. */
    static #fieldUInt16LE(name: string, offset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 65535,
            decode: function (this: SLMP): void {
                const b: Buffer = this.readBytes(offset, 2)
                ;(this.instance as any)[name].setValue(b[0] | (b[1] << 8))
            },
            encode: function (this: SLMP): void {
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

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SLMP subheader=${subheader} len=${requestDataLength}',
            properties: {
                //The 2-byte frame marker, kept in wire order (big-endian): 0x5000 (`50 00`) request,
                //0xD000 (`D0 00`) response. Not little-endian — it is a fixed signature, not a value.
                subheader: this.fieldUInt('subheader', 0, 2, 'Subheader'),
                networkNo: this.fieldUInt('networkNo', 2, 1, 'Network Number'),
                stationNo: this.fieldUInt('stationNo', 3, 1, 'Station Number'),
                //Request-destination Module I/O number (little-endian, e.g. 0x03FF = own station).
                moduleIO: this.#fieldUInt16LE('moduleIO', 4, 'Module I/O Number'),
                multidropStation: this.fieldUInt('multidropStation', 6, 1, 'Multidrop Station Number'),
                //Counts every byte that FOLLOWS this field (Monitor Timer + Command + Subcommand + device
                //data on a request; End Code + data on a response). Honored when supplied (a crafted frame
                //may lie); else derived from the encoded `data` length.
                requestDataLength: {
                    type: 'integer',
                    label: 'Request Data Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: SLMP): void {
                        const b: Buffer = this.readBytes(7, 2)
                        this.instance.requestDataLength.setValue(b[0] | (b[1] << 8))
                    },
                    encode: function (this: SLMP): void {
                        const provided: number | undefined = this.instance.requestDataLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.data.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.requestDataLength.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.requestDataLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.requestDataLength.setValue(value)
                        this.writeBytes(7, Buffer.from([value & 0xff, (value >> 8) & 0xff]))
                    }
                },
                //The command-specific remainder, kept verbatim. Bounded by Request Data Length (the frame
                //ends at offset 9 + length) and the captured bytes, so trailing / pipelined data is left
                //to the codec's recursion / RawData.
                data: {
                    type: 'string',
                    label: 'Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SLMP): void {
                        const available: number = this.packet.length - this.startPos
                        const length: number = this.instance.requestDataLength.getValue(0)
                        let end: number = 9 + length
                        if (end > available) end = available
                        this.instance.data.setValue(end > 9 ? BufferToHex(this.readBytes(9, end - 9)) : '')
                    },
                    encode: function (this: SLMP): void {
                        const data: string = this.instance.data.getValue('')
                        if (data) this.writeBytes(9, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 'slmp'

    public readonly name: string = 'SeamLess Message Protocol'

    public readonly nickname: string = 'SLMP'

    //MELSEC SLMP rides TCP/UDP port 5007 (selected via the tcpport:5007 / udpport:5007 buckets). This
    //stays a port-bucket protocol: matchKeys only, NO heuristicFallback — the subheader is only a 2-byte
    //marker, too weak to claim SLMP off port 5007, so non-SLMP 5007 traffic falls through to raw.
    public readonly matchKeys: string[] = ['tcpport:5007', 'udpport:5007']

    public match(): boolean {
        //SLMP rides TCP/UDP port 5007. Require the full 9-byte 3E-frame header and a valid 3E-binary
        //subheader (0x5000 request or 0xD000 response) so non-SLMP 5007 traffic falls through to raw.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp' && this.prevCodecModule.id !== 'udp') return false
        if (this.packet.length - this.startPos < 9) return false
        const subheader: string = BufferToHex(this.readBytes(0, 2, true))
        return subheader === '5000' || subheader === 'd000'
    }

    //A leaf header — the command-specific device payload requires per-command parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
