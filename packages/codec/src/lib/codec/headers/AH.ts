import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt8} from '../../helper/BufferToNumber'
import {UInt8ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * AH — IP Authentication Header (RFC 4302), carried directly over IP as protocol 51. Like the IPv6
 * extension headers it is a next-header-chained shim, not a leaf: a fixed 12-byte prefix — Next Header
 * (the IP-protocol number of what it protects), Payload Len (the whole AH's length in 4-octet words
 * minus 2), a 2-byte Reserved, a 32-bit Security Parameters Index and a 32-bit Sequence Number —
 * followed by a variable Integrity Check Value whose length is (PayloadLen+2)*4 - 12 octets (12 for
 * the ubiquitous HMAC-SHA1-96). The protected upper-layer payload follows and is left to the codec's
 * recursion: AH's Next Header drives the same `ipproto` demux dimension IPv4/IPv6 use, so a transport-
 * mode AH over UDP recurses into UDP, while an unrecognised next-header falls through to RawData.
 *
 * The ICV is honored verbatim, not recomputed (AH is a faithful executor — it cannot rederive an HMAC
 * without the SA key), and Payload Len is honored-else-derived: a supplied value is kept, an absent one
 * is computed from the ICV length. A well-formed AH message round-trips byte-for-byte.
 */
export class AH extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    //Byte length of the ICV written during encode; consumed by the Payload Len derive handler.
    #icvByteLength: number = 0

    public get SCHEMA(): ProtocolJSONSchema {
        return (AH.#schemaCache ??= AH.#buildSchema())
    }

    /**
     * The length available to AH's own header (fixed prefix + ICV), bounded by the enclosing IP
     * datagram — so a lying Payload Len near the end of the IP payload does not read into a trailing
     * FCS. The protected inner payload is left to the codec's recursion.
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
            summary: 'AH spi=${spi} seq=${sequenceNumber}',
            properties: {
                //Next Header is an IP-protocol number (the type of the protected payload); stored as
                //`nxt` — the field name IPv6 extension headers use — so the `ipproto` demux routes the
                //inner layer and TCP/UDP's `nxt`-aware match() accepts AH as a parent.
                nxt: this.fieldUInt('nxt', 0, 1, 'Next Header'),
                //AH total length in 4-octet words minus 2. Honored-else-derived: a supplied value is
                //kept verbatim, an absent (0) one is recomputed from the encoded ICV length.
                payloadLen: {
                    type: 'integer',
                    label: 'Payload Length',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: AH): void {
                        this.instance.payloadLen.setValue(BufferToUInt8(this.readBytes(1, 1)))
                    },
                    encode: function (this: AH): void {
                        const payloadLen: number = this.instance.payloadLen.getValue(0)
                        this.instance.payloadLen.setValue(payloadLen)
                        this.writeBytes(1, UInt8ToBuffer(payloadLen))
                        if (!payloadLen) {
                            this.addPostSelfEncodeHandler((): void => {
                                //Fixed prefix is 12 octets (3 words); total = 12 + ICV octets, and
                                //Payload Len = totalWords - 2 = (12 + icvBytes)/4 - 2 = icvBytes/4 + 1.
                                const derived: number = Math.max(0, Math.ceil((12 + this.#icvByteLength) / 4) - 2)
                                this.instance.payloadLen.setValue(derived)
                                this.writeBytes(1, UInt8ToBuffer(derived))
                            })
                        }
                    }
                },
                reserved: this.fieldHex('reserved', 2, 2, 'Reserved'),
                spi: this.fieldUInt('spi', 4, 4, 'Security Parameters Index'),
                sequenceNumber: this.fieldUInt('sequenceNumber', 8, 4, 'Sequence Number'),
                //Integrity Check Value: variable length driven by Payload Len, bounded by the IP payload
                //so a lying length cannot read past the datagram. Honored verbatim — an HMAC cannot be
                //rederived without the SA key.
                icv: {
                    type: 'string',
                    label: 'Integrity Check Value',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: AH): void {
                        const payloadLen: number = this.instance.payloadLen.getValue(0)
                        const available: number = this.#available()
                        let icvLength: number = (payloadLen + 2) * 4 - 12
                        if (icvLength < 0) icvLength = 0
                        if (12 + icvLength > available) icvLength = Math.max(0, available - 12)
                        this.instance.icv.setValue(BufferToHex(this.readBytes(12, icvLength)))
                    },
                    encode: function (this: AH): void {
                        const icvBuffer: Buffer = HexToBuffer(this.instance.icv.getValue(''))
                        this.#icvByteLength = icvBuffer.length
                        this.writeBytes(12, icvBuffer)
                    }
                }
            }
        }
    }

    public readonly id: string = 'ah'

    public readonly name: string = 'IP Authentication Header'

    public readonly nickname: string = 'AH'

    public readonly isProtocol: boolean = false

    public readonly matchKeys: string[] = ['ipproto:51']

    //Extension-header style: it consumes ipproto:51 and produces the next-header key for the protected
    //payload after it (mirrors the IPv6 Hop-by-Hop header).
    public readonly demuxProducers: DemuxProducer[] = [{field: 'nxt', namespace: 'ipproto', kind: 'uint'}]

    public match(): boolean {
        //AH sits directly above IPv4 (protocol field) or IPv6 (next-header field) with protocol 51, and
        //needs at least its 12-byte fixed prefix within the IP payload.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.instance.protocol.getValue() !== 0x33 && this.prevCodecModule.instance.nxt.getValue() !== 0x33) return false
        return this.#available() >= 12
    }

}
