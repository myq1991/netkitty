import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One TFTP option (RFC 2347): a name and value, each a null-terminated string on the wire. */
type TFTPOption = {name: string, value: string}

/**
 * TFTP — Trivial File Transfer Protocol (RFC 1350, options RFC 2347). Each message starts with a
 * 2-byte opcode: RRQ(1)/WRQ(2) = filename + mode (both null-terminated) + optional name/value options;
 * DATA(3) = block-number(2) + data; ACK(4) = block-number(2); ERROR(5) = error-code(2) + message
 * (null-terminated); OACK(6) = name/value options.
 *
 * Only the initial RRQ/WRQ rides the well-known UDP port 69; the ensuing DATA/ACK transfer moves to a
 * server-chosen ephemeral port (a TID), so those packets are a stateful conversation that belongs to
 * the reassembly/conversation layer, not this single-packet, port-69 codec. The codec decodes every
 * opcode structurally (so a DATA/ACK reached by other means still parses), but demux only claims
 * port-69 traffic. Strings are kept verbatim (latin1) and re-emitted with their null terminator; DATA
 * payload is kept as raw hex — so a well-formed message round-trips byte-for-byte. (A truncated string
 * missing its RFC-mandated null terminator is malformed: it decodes best-effort but re-emits with the
 * terminator, so it is not byte-perfect — the byte-perfect guarantee is for standard-conformant TFTP.)
 */
export class TFTP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (TFTP.#schemaCache ??= TFTP.#buildSchema())
    }

    /** The payload length bounded by the UDP datagram (so a retained FCS/padding is not absorbed). */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /** Read a null-terminated string at `offset` (bounded by `available`); returns it plus the offset past the terminator. */
    #readCString(offset: number, available: number): {value: string, next: number} {
        let p: number = offset
        while (p < available && this.readBytes(p, 1, true)[0] !== 0) p++
        const value: string = p > offset ? this.readBytes(offset, p - offset).toString('latin1') : ''
        let next: number = p
        if (p < available) {
            this.readBytes(p, 1) //consume the null terminator (extends headerLength)
            next = p + 1
        }
        return {value: value, next: next}
    }

    /** Read a run of null-terminated name/value option pairs from `offset` to `available`. */
    #readOptions(offset: number, available: number): {options: TFTPOption[], next: number} {
        const options: TFTPOption[] = []
        let o: number = offset
        while (o < available) {
            const name: {value: string, next: number} = this.#readCString(o, available)
            if (name.next >= available && name.value === '') break
            const value: {value: string, next: number} = this.#readCString(name.next, available)
            options.push({name: name.value, value: value.value})
            o = value.next
        }
        return {options: options, next: o}
    }

    #writeCString(offset: number, value: string): number {
        const bytes: Buffer = Buffer.from(value ? value : '', 'latin1')
        this.writeBytes(offset, bytes)
        this.writeBytes(offset + bytes.length, Buffer.from([0]))
        return offset + bytes.length + 1
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'TFTP opcode=${opcode}',
            properties: {
                //Opcode-driven layout, so the whole message is parsed/emitted here; the fields below
                //carry only schema metadata and are populated per opcode.
                opcode: {
                    type: 'integer',
                    label: 'Opcode',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: TFTP): void {
                        const available: number = this.#payloadLength()
                        if (available < 2) {
                            //Too short to hold even the 2-byte opcode. match() already prevents claiming
                            //such a payload; seed a valid (schema-shaped) instance defensively so the
                            //decode result is always re-encodable (never an undefined-data layer).
                            this.instance.opcode.setValue(0)
                            return
                        }
                        const opcode: number = BufferToUInt16(this.readBytes(0, 2))
                        this.instance.opcode.setValue(opcode)
                        let offset: number = 2
                        switch (opcode) {
                            case 1:
                            case 2: {
                                const filename: {value: string, next: number} = this.#readCString(offset, available)
                                const mode: {value: string, next: number} = this.#readCString(filename.next, available)
                                this.instance.filename.setValue(filename.value)
                                this.instance.mode.setValue(mode.value)
                                this.instance.options.setValue(this.#readOptions(mode.next, available).options)
                                break
                            }
                            case 3: {
                                this.instance.block.setValue(available >= 4 ? BufferToUInt16(this.readBytes(offset, 2)) : 0)
                                offset += 2
                                this.instance.data.setValue(offset < available ? BufferToHex(this.readBytes(offset, available - offset)) : '')
                                break
                            }
                            case 4: {
                                this.instance.block.setValue(available >= 4 ? BufferToUInt16(this.readBytes(offset, 2)) : 0)
                                break
                            }
                            case 5: {
                                this.instance.errorCode.setValue(available >= 4 ? BufferToUInt16(this.readBytes(offset, 2)) : 0)
                                offset += 2
                                this.instance.errorMessage.setValue(this.#readCString(offset, available).value)
                                break
                            }
                            case 6: {
                                this.instance.options.setValue(this.#readOptions(offset, available).options)
                                break
                            }
                            default: {
                                //Unknown opcode: keep the body verbatim for a byte-perfect round-trip.
                                this.instance.rawBody.setValue(offset < available ? BufferToHex(this.readBytes(offset, available - offset)) : '')
                            }
                        }
                    },
                    encode: function (this: TFTP): void {
                        const opcode: number = this.instance.opcode.getValue(0)
                        this.writeBytes(0, UInt16ToBuffer(opcode))
                        let offset: number = 2
                        switch (opcode) {
                            case 1:
                            case 2: {
                                offset = this.#writeCString(offset, this.instance.filename.getValue(''))
                                offset = this.#writeCString(offset, this.instance.mode.getValue(''))
                                const options: TFTPOption[] = this.instance.options.getValue([])
                                if (options) for (const option of options) {
                                    offset = this.#writeCString(offset, option.name ? option.name : '')
                                    offset = this.#writeCString(offset, option.value ? option.value : '')
                                }
                                break
                            }
                            case 3: {
                                this.writeBytes(offset, UInt16ToBuffer(this.instance.block.getValue(0)))
                                offset += 2
                                const data: Buffer = HexToBuffer(this.instance.data.getValue(''))
                                if (data.length) this.writeBytes(offset, data)
                                break
                            }
                            case 4: {
                                this.writeBytes(offset, UInt16ToBuffer(this.instance.block.getValue(0)))
                                break
                            }
                            case 5: {
                                this.writeBytes(offset, UInt16ToBuffer(this.instance.errorCode.getValue(0)))
                                offset += 2
                                this.#writeCString(offset, this.instance.errorMessage.getValue(''))
                                break
                            }
                            case 6: {
                                const options: TFTPOption[] = this.instance.options.getValue([])
                                if (options) for (const option of options) {
                                    offset = this.#writeCString(offset, option.name ? option.name : '')
                                    offset = this.#writeCString(offset, option.value ? option.value : '')
                                }
                                break
                            }
                            default: {
                                const rawBody: string = this.instance.rawBody.getValue('')
                                if (rawBody) this.writeBytes(offset, HexToBuffer(rawBody))
                            }
                        }
                    }
                },
                filename: {type: 'string', label: 'File Name'},
                mode: {type: 'string', label: 'Mode'},
                block: {type: 'integer', label: 'Block Number', minimum: 0, maximum: 65535},
                errorCode: {type: 'integer', label: 'Error Code', minimum: 0, maximum: 65535},
                errorMessage: {type: 'string', label: 'Error Message'},
                data: {type: 'string', label: 'Data', contentEncoding: StringContentEncodingEnum.HEX},
                options: {
                    type: 'array',
                    label: 'Options',
                    items: {
                        type: 'object',
                        label: 'Option',
                        properties: {
                            name: {type: 'string', label: 'Name'},
                            value: {type: 'string', label: 'Value'}
                        }
                    }
                },
                rawBody: {type: 'string', label: 'Body', contentEncoding: StringContentEncodingEnum.HEX, hidden: true}
            }
        }
    }

    public readonly id: string = 'tftp'

    public readonly name: string = 'Trivial File Transfer Protocol'

    public readonly nickname: string = 'TFTP'

    //Only the initial RRQ/WRQ uses the well-known port 69; the DATA/ACK transfer moves to an ephemeral
    //TID (a stateful conversation for the reassembly layer), so demux claims port 69 only.
    public readonly matchKeys: string[] = ['udpport:69']

    public match(): boolean {
        //Require at least the 2-byte opcode within the UDP payload — a shorter datagram on port 69 is
        //not a TFTP message and must fall through to raw (rather than claim an un-decodable layer).
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp' && this.#payloadLength() >= 2
    }

    //A leaf header — nothing demuxes above TFTP.
    public readonly demuxProducers: DemuxProducer[] = []

}
