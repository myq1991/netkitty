import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One DHCPv6 option: an option-code and its verbatim hex data (option-len is derived on encode). */
type DHCPv6Option = {code: number, value: string}

/**
 * DHCPv6 — Dynamic Host Configuration Protocol for IPv6 (RFC 8415). A client/server message is a
 * 1-byte message-type, a 3-byte transaction-id, then options in a regular code-length-value form:
 * option-code(2) + option-len(2) + option-data(option-len), no padding. Rides UDP, client port 546 and
 * server port 547 (over IPv6, multicast ff02::1:2).
 *
 * Options are carried generically (code + verbatim hex data) so every option — including ones whose
 * data is itself nested options (IA_NA/IA_PD) — round-trips byte-for-byte; per-option / nested decoding
 * is a later enrichment. Relay-agent messages (RELAY-FORW 12 / RELAY-REPL 13) have a DIFFERENT body
 * (hop-count + 2 IPv6 addresses + options), so their body is kept verbatim (rawBody) rather than
 * misparsed as a transaction-id, preserving a byte-perfect round-trip.
 */
export class DHCPv6 extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    static readonly #RELAY_MESSAGE_TYPES: ReadonlySet<number> = new Set([12, 13])

    public get SCHEMA(): ProtocolJSONSchema {
        return (DHCPv6.#schemaCache ??= DHCPv6.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'DHCPv6 type=${msgType} xid=${transactionId}',
            properties: {
                //DHCPv6 is message-type-driven (the transaction-id vs relay body shape depends on it), so
                //the whole message is parsed/emitted here; the fields below carry only schema metadata.
                msgType: {
                    type: 'integer',
                    label: 'Message Type',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: DHCPv6): void {
                        let available: number = this.packet.length - this.startPos
                        if (available < 1) return
                        //Bound options/body by the UDP payload length, not the whole captured frame, so a
                        //retained Ethernet FCS or L2 padding after the datagram is not swallowed as bogus
                        //options — it spills to the raw layer and the packet still round-trips byte-perfect.
                        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
                            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
                            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
                        }
                        const msgType: number = BufferToUInt8(this.readBytes(0, 1))
                        this.instance.msgType.setValue(msgType)
                        if (DHCPv6.#RELAY_MESSAGE_TYPES.has(msgType)) {
                            //Relay-agent message: hop-count(1) + link-address(16) + peer-address(16) +
                            //options — a different shape, kept verbatim for a byte-perfect round-trip.
                            if (available > 1) this.instance.rawBody.setValue(BufferToHex(this.readBytes(1, available - 1)))
                            else this.instance.rawBody.setValue('')
                            return
                        }
                        this.instance.transactionId.setValue(BufferToHex(this.readBytes(1, 3)))
                        const options: DHCPv6Option[] = []
                        let offset: number = 4
                        //Each option is code(2) len(2) data(len), no terminator. Peek the header (dry-run,
                        //so it does not extend headerLength), and if the option data would overrun the
                        //payload, stop and leave the tail to the raw layer — keeping both truncated
                        //captures and trailing padding byte-perfect. offset advances ≥4 each iteration.
                        while (offset + 4 <= available) {
                            const header: Buffer = this.readBytes(offset, 4, true)
                            const code: number = BufferToUInt16(header.subarray(0, 2))
                            const length: number = BufferToUInt16(header.subarray(2, 4))
                            if (offset + 4 + length > available) break
                            const optionBuffer: Buffer = this.readBytes(offset, 4 + length)
                            options.push({code: code, value: length ? BufferToHex(optionBuffer.subarray(4)) : ''})
                            offset += 4 + length
                        }
                        this.instance.options.setValue(options)
                    },
                    encode: function (this: DHCPv6): void {
                        const msgType: number = this.instance.msgType.getValue(0)
                        this.writeBytes(0, UInt8ToBuffer(msgType))
                        const rawBody: string = this.instance.rawBody.getValue('')
                        //Relay-agent messages (and any message carrying a verbatim body) re-emit rawBody
                        //as-is — keyed on the message type so a degenerate empty-body relay stays 1 byte.
                        if (rawBody || DHCPv6.#RELAY_MESSAGE_TYPES.has(msgType)) {
                            if (rawBody) this.writeBytes(1, HexToBuffer(rawBody))
                            return
                        }
                        //transaction-id is a fixed 3 bytes — fit any crafted hex to exactly 3 so it never
                        //shifts the following options (short is left-padded, long is truncated).
                        this.writeBytes(1, HexToBuffer(this.instance.transactionId.getValue('000000'), 3).subarray(0, 3))
                        let offset: number = 4
                        const options: DHCPv6Option[] = this.instance.options.getValue([])
                        if (options) {
                            for (const option of options) {
                                const value: Buffer = HexToBuffer(option.value ? option.value : '')
                                this.writeBytes(offset, UInt16ToBuffer(option.code ? option.code : 0))
                                this.writeBytes(offset + 2, UInt16ToBuffer(value.length))
                                offset += 4
                                if (value.length) {
                                    this.writeBytes(offset, value)
                                    offset += value.length
                                }
                            }
                        }
                    }
                },
                transactionId: {type: 'string', label: 'Transaction ID', contentEncoding: StringContentEncodingEnum.HEX},
                //Verbatim body for relay-agent messages (RELAY-FORW/RELAY-REPL); empty and hidden for the
                //common client/server messages, which use transactionId + options.
                rawBody: {type: 'string', label: 'Relay Body', contentEncoding: StringContentEncodingEnum.HEX, hidden: true},
                options: {
                    type: 'array',
                    label: 'Options',
                    items: {
                        type: 'object',
                        label: 'Option',
                        properties: {
                            code: {type: 'integer', label: 'Option Code', minimum: 0, maximum: 65535},
                            value: {type: 'string', label: 'Option Data', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'dhcpv6'

    public readonly name: string = 'Dynamic Host Configuration Protocol for IPv6'

    public readonly nickname: string = 'DHCPv6'

    //Client port 546, server port 547 (both UDP, over IPv6). Port-defined (no content signature).
    public readonly matchKeys: string[] = ['udpport:546', 'udpport:547']

    public match(): boolean {
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp'
    }

    //A leaf header — nothing demuxes above DHCPv6.
    public readonly demuxProducers: DemuxProducer[] = []

}
