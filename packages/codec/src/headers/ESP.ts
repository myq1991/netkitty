import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt32} from '../helper/BufferToNumber'
import {UInt32ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * ESP — IP Encapsulating Security Payload (RFC 4303), carried directly over IP as protocol 50 (both
 * IPv4 `protocol` and IPv6 `nxt`). The cleartext header is just two big-endian 32-bit words: the SPI
 * (Security Parameters Index — identifies the Security Association, together with the destination
 * address and protocol) and a monotonic Sequence Number (anti-replay counter). Everything after those
 * eight bytes — the encapsulated payload, the trailing Pad / Pad Length / Next Header, and the optional
 * Integrity Check Value — is protected by the SA's cipher/authenticator and is opaque on the wire.
 *
 * A dissector cannot split that opaque region without the SA keys (which are out of band), so ESP is a
 * leaf header: the SPI and Sequence Number are surfaced, and the remaining bytes are kept verbatim as
 * `encryptedPayload` hex, bounded by the enclosing IP datagram so a trailing FCS/padding is not pulled
 * in. Nothing is recomputed on encode (a faithful executor carries the ciphertext as-is), so a
 * well-formed ESP packet round-trips byte-for-byte.
 */
export class ESP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (ESP.#schemaCache ??= ESP.#buildSchema())
    }

    /**
     * Bytes available to ESP within the enclosing IP datagram — so a short IP payload does not let the
     * verbatim `encryptedPayload` read into a trailing Ethernet FCS or padding. Bounds the payload read.
     */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'ipv4') {
            const ipPayload: number = prev.instance.length.getValue(0) - prev.length
            if (ipPayload >= 0 && ipPayload < available) available = ipPayload
        } else if (prev && prev.id === 'ipv6') {
            const ipPayload: number = prev.instance.plen.getValue(0)
            if (ipPayload >= 0 && ipPayload < available) available = ipPayload
        }
        return available < 0 ? 0 : available
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'ESP spi=${spi} seq=${sequenceNumber}',
            properties: {
                //Security Parameters Index — big-endian 32-bit SA selector.
                spi: {
                    type: 'integer',
                    label: 'SPI',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: ESP): void {
                        this.instance.spi.setValue(BufferToUInt32(this.readBytes(0, 4)))
                    },
                    encode: function (this: ESP): void {
                        const node: any = this.instance.spi
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
                        this.writeBytes(0, UInt32ToBuffer(value))
                    }
                },
                //Anti-replay sequence number — big-endian 32-bit, monotonically increasing per SA.
                sequenceNumber: {
                    type: 'integer',
                    label: 'Sequence Number',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: ESP): void {
                        this.instance.sequenceNumber.setValue(BufferToUInt32(this.readBytes(4, 4)))
                    },
                    encode: function (this: ESP): void {
                        const node: any = this.instance.sequenceNumber
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
                        this.writeBytes(4, UInt32ToBuffer(value))
                    }
                },
                //The encrypted payload + padding + Pad Length + Next Header + optional ICV. Opaque without
                //the SA keys, so it is kept verbatim as hex; bounded by the IP datagram so a trailing FCS/
                //padding is left to the codec's recursion / RawData.
                encryptedPayload: {
                    type: 'string',
                    label: 'Encrypted Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: ESP): void {
                        const end: number = this.#available()
                        this.instance.encryptedPayload.setValue(end > 8 ? BufferToHex(this.readBytes(8, end - 8)) : '')
                    },
                    encode: function (this: ESP): void {
                        const data: string = this.instance.encryptedPayload.getValue('')
                        if (data) this.writeBytes(8, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 'esp'

    public readonly name: string = 'IP Encapsulating Security Payload'

    public readonly nickname: string = 'ESP'

    public readonly matchKeys: string[] = ['ipproto:50']

    public match(): boolean {
        //ESP sits directly above IPv4 (protocol field) or IPv6 (next-header field) with protocol 50, and
        //needs at least its 8-byte cleartext header (SPI + Sequence Number) within the IP payload.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.instance.protocol.getValue() !== 0x32 && this.prevCodecModule.instance.nxt.getValue() !== 0x32) return false
        return this.#available() >= 8
    }

    //A leaf header — the payload is encrypted and cannot be dissected further without the SA keys.
    public readonly demuxProducers: DemuxProducer[] = []

}
