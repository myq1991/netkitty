import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * EtherCAT — Ethernet for Control Automation Technology (IEC 61158 Type 12), carried directly in an
 * Ethernet II frame with EtherType 0x88A4 (an Ethernet child — no IP/UDP). Immediately after the Ethernet
 * header comes a 2-byte EtherCAT header, then the EtherCAT datagram chain.
 *
 * ⚠️ Unlike most of the codec's protocols (which are big-endian), the 2-byte EtherCAT header is a single
 * LITTLE-ENDIAN uint16. There is no little-endian helper in this codebase, so the header word is read and
 * written byte-by-byte in the closures (see ENIP for the precedent). Within that 16-bit LE value `h`:
 *   - Length   = bits 0..10  (11 bits) = byte count of all datagrams that follow the 2-byte header.
 *   - Reserved = bit 11      (1 bit)   = preserved verbatim for a byte-perfect round-trip.
 *   - Type     = bits 12..15 (4 bits)  = 1 for EtherCAT commands (DLPDUs); other values exist.
 * So `length = h & 0x07FF`, `reserved = (h >> 11) & 0x1`, `type = (h >> 12) & 0x0F`; and on encode
 * `h = (length & 0x07FF) | ((reserved & 1) << 11) | ((type & 0x0F) << 12)`, written LITTLE-ENDIAN as
 * `[h & 0xff, (h >> 8) & 0xff]`.
 *
 * The datagram chain (each datagram: 10-byte header + data + 2-byte working counter) is command-dependent,
 * addressed, chainable state, so this minimal slice keeps it verbatim as `data` hex (byte-perfect), bounded
 * by the Length field (data ends at offset 2 + Length, clamped to the captured bytes). Anything after the
 * Length-bounded region is left to the codec's recursion / RawData (e.g. Ethernet padding). Structuring the
 * datagram chain (Cmd/Idx/Address/Len/IRQ/WKC per datagram) is a deferred slice. Length is honor-else-derive
 * on encode: honored when supplied (a crafted frame may carry any Length), else derived from the data.
 */
export class EtherCAT extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (EtherCAT.#schemaCache ??= EtherCAT.#buildSchema())
    }

    /** Read the 2-byte EtherCAT header as a little-endian uint16. */
    static #readHeaderWord(header: EtherCAT): number {
        const b: Buffer = header.readBytes(0, 2)
        return b[0] | (b[1] << 8)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'EtherCAT type=${type} len=${length}',
            properties: {
                //length/reserved/type all live in the same 2 header bytes (one little-endian uint16), so
                //each decodes from that single LE word by extracting its bits. Only `length` has an encode:
                //it re-reads all three instance values, assembles the full word, and writes the 2 bytes once
                //(so the three fields never clobber each other). reserved/type are decode-only.
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    //The on-wire field is 11 bits (max 0x7FF); the schema bound is left wider (uint16) so an
                    //over-range value reaches the encode closure and is clamped+recorded there (an 11-bit
                    //Ajv cap would silently reject it at the entry point instead).
                    maximum: 65535,
                    decode: function (this: EtherCAT): void {
                        this.instance.length.setValue(EtherCAT.#readHeaderWord(this) & 0x07FF)
                    },
                    encode: function (this: EtherCAT): void {
                        //Length counts only the datagram bytes that follow the 2-byte header. Honored when
                        //supplied (a crafted frame may lie); else derived from the data byte count.
                        const provided: number | undefined = this.instance.length.getValue()
                        let length: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.data.getValue('')).length
                        //Length is an 11-bit field (max 0x7FF). A larger value cannot be represented, so
                        //clamp it and record the error rather than letting it wrap into the Type/Reserved
                        //bits (which would corrupt the header word).
                        if (length > 0x7FF) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 2047')
                            length = 0x7FF
                        }
                        if (length < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            length = 0
                        }
                        this.instance.length.setValue(length)
                        const reserved: number = this.instance.reserved.getValue(0) & 0x1
                        const type: number = this.instance.type.getValue(0) & 0x0F
                        const h: number = (length & 0x07FF) | (reserved << 11) | (type << 12)
                        this.writeBytes(0, Buffer.from([h & 0xff, (h >> 8) & 0xff]))
                    }
                },
                reserved: {
                    type: 'integer',
                    label: 'Reserved',
                    minimum: 0,
                    maximum: 1,
                    default: 0,
                    //Decode-only: bit 11 of the LE header word. Written by `length`'s encode (see above).
                    decode: function (this: EtherCAT): void {
                        this.instance.reserved.setValue((EtherCAT.#readHeaderWord(this) >> 11) & 0x1)
                    }
                },
                type: {
                    type: 'integer',
                    label: 'Type',
                    minimum: 0,
                    maximum: 15,
                    default: 1,
                    //Decode-only: bits 12..15 of the LE header word. Written by `length`'s encode (see above).
                    decode: function (this: EtherCAT): void {
                        this.instance.type.setValue((EtherCAT.#readHeaderWord(this) >> 12) & 0x0F)
                    }
                },
                //The EtherCAT datagram chain, kept verbatim (byte-perfect). Bounded by the Length field
                //(data ends at offset 2 + Length) and the captured bytes, so trailing padding / pipelined
                //bytes are left to the codec's recursion / RawData. Datagram structuring is a deferred slice.
                data: {
                    type: 'string',
                    label: 'Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: EtherCAT): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        let end: number = 2 + length
                        if (end > remaining) end = remaining
                        this.instance.data.setValue(end > 2 ? BufferToHex(this.readBytes(2, end - 2)) : '')
                    },
                    encode: function (this: EtherCAT): void {
                        const data: string = this.instance.data.getValue('')
                        if (data) this.writeBytes(2, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 'ecat'

    public readonly name: string = 'EtherCAT'

    public readonly nickname: string = 'EtherCAT'

    public readonly matchKeys: string[] = ['ethertype:88a4']

    public match(): boolean {
        //An Ethernet child selected by EtherType 0x88A4 (stored as a lowercase 4-hex string). Require the
        //2-byte minimum for the EtherCAT header.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'eth') return false
        if (this.prevCodecModule.instance.etherType.getValue() !== '88a4') return false
        return this.packet.length - this.startPos >= 2
    }

    //A leaf header — the datagram chain requires command-dependent, addressed parsing (deferred slice).
    public readonly demuxProducers: DemuxProducer[] = []

}
