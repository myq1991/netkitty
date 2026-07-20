import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * DNP3 — Distributed Network Protocol 3 (IEEE 1815), a SCADA protocol common in electric/water
 * utilities, on TCP/UDP port 20000. Each frame begins with a 10-byte Data Link Layer header: the start
 * bytes 0x0564, a Length (count of the octets from Control through the user data, excluding CRCs), a
 * Control octet (DIR / PRM / FCB / FCV(or DFC) / 4-bit Function Code), a little-endian Destination and
 * Source address, and a header CRC. The user data that follows is carried in blocks of up to 16 octets
 * each with its own trailing 2-byte CRC.
 *
 * This codec decodes the link header structurally and keeps the data-block region (transport header +
 * application data + the per-block CRCs) verbatim as `payload` hex — de-blocking those CRCs to recover
 * the transport/application layer is a cross-frame reassembly concern, not a single-packet one. The CRCs
 * are honored verbatim (never recomputed), so a well-formed frame round-trips byte-for-byte; the frame's
 * extent is derived from the Length field so a pipelined/trailing frame is left to RawData.
 */
export class DNP3 extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (DNP3.#schemaCache ??= DNP3.#buildSchema())
    }

    /** A single bit of the Control octet (byte 3, bit 0 = MSB). */
    static #flagBit(name: string, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'boolean',
            label: label,
            decode: function (this: DNP3): void {
                (this.instance.control as any)[name].setValue(!!this.readBits(3, 1, bitOffset, 1))
            },
            encode: function (this: DNP3): void {
                const value: boolean = !!(this.instance.control as any)[name].getValue()
                ;(this.instance.control as any)[name].setValue(value)
                this.writeBits(3, 1, bitOffset, 1, value ? 1 : 0)
            }
        }
    }

    /** The total on-wire frame length derived from the Length field: 10-byte header + data blocks (each
     * up to 16 data octets plus a 2-byte CRC). */
    #frameLength(): number {
        const length: number = this.instance.length.getValue(0)
        const userData: number = length > 5 ? length - 5 : 0
        const blocks: number = Math.ceil(userData / 16)
        return 10 + userData + blocks * 2
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'DNP3 func=${control.functionCode} ${source}->${destination}',
            properties: {
                start: this.fieldHex('start', 0, 2, 'Start'),
                length: this.fieldUInt('length', 2, 1, 'Length'),
                //Control octet (byte 3, MSB first): DIR / PRM / FCB / FCV(or DFC) / Function Code(4 bits).
                control: {
                    type: 'object',
                    label: 'Control',
                    properties: {
                        dir: this.#flagBit('dir', 0, 'Direction'),
                        prm: this.#flagBit('prm', 1, 'Primary'),
                        fcb: this.#flagBit('fcb', 2, 'Frame Count Bit'),
                        fcv: this.#flagBit('fcv', 3, 'Frame Count Valid'),
                        functionCode: {
                            type: 'integer',
                            label: 'Function Code',
                            minimum: 0,
                            maximum: 15,
                            decode: function (this: DNP3): void { this.instance.control.functionCode.setValue(this.readBits(3, 1, 4, 4)) },
                            encode: function (this: DNP3): void { this.writeBits(3, 1, 4, 4, this.instance.control.functionCode.getValue(0)) }
                        }
                    }
                },
                //Destination and Source are 16-bit little-endian link addresses.
                destination: {
                    type: 'integer',
                    label: 'Destination',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: DNP3): void {
                        const bytes: Buffer = this.readBytes(4, 2)
                        this.instance.destination.setValue(bytes[0] | (bytes[1] << 8))
                    },
                    encode: function (this: DNP3): void {
                        const value: number = this.instance.destination.getValue(0)
                        this.writeBytes(4, Buffer.from([value & 0xff, (value >> 8) & 0xff]))
                    }
                },
                source: {
                    type: 'integer',
                    label: 'Source',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: DNP3): void {
                        const bytes: Buffer = this.readBytes(6, 2)
                        this.instance.source.setValue(bytes[0] | (bytes[1] << 8))
                    },
                    encode: function (this: DNP3): void {
                        const value: number = this.instance.source.getValue(0)
                        this.writeBytes(6, Buffer.from([value & 0xff, (value >> 8) & 0xff]))
                    }
                },
                //Header CRC over the preceding 8 octets, honored verbatim (never recomputed).
                headerCrc: this.fieldHex('headerCrc', 8, 2, 'Header CRC'),
                //The data-block region: transport header + application data + per-block CRCs, kept verbatim.
                //Bounded by the Length-derived frame extent so a pipelined/trailing frame is left to raw.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: DNP3): void {
                        const remaining: number = this.packet.length - this.startPos
                        let end: number = this.#frameLength()
                        if (end > remaining) end = remaining
                        this.instance.payload.setValue(end > 10 ? BufferToHex(this.readBytes(10, end - 10)) : '')
                    },
                    encode: function (this: DNP3): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(10, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'dnp3'

    public readonly name: string = 'Distributed Network Protocol 3'

    public readonly nickname: string = 'DNP3'

    public readonly matchKeys: string[] = ['tcpport:20000', 'udpport:20000']

    public match(): boolean {
        //DNP3 rides on TCP/UDP port 20000. Require the 10-byte link header and the 0x0564 start signature.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp' && this.prevCodecModule.id !== 'udp') return false
        if (this.packet.length - this.startPos < 10) return false
        const start: Buffer = this.readBytes(0, 2, true)
        return start[0] === 0x05 && start[1] === 0x64
    }

    //A leaf header — the transport/application layers require de-blocking (a reassembly concern).
    public readonly demuxProducers: DemuxProducer[] = []

}
