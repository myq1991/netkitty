import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * OPC UA PubSub — UADP NetworkMessage (IEC 62541-14 / OPC 10000-14), UDP port 4840. A UADP
 * NetworkMessage begins with a single UADPFlags octet: the low nibble is the UADPVersion (1 in the
 * current spec) and the four high bits are enable flags — PublisherId (bit 4, 0x10), GroupHeader
 * (bit 5, 0x20), PayloadHeader (bit 6, 0x40) and ExtendedFlags1 (bit 7, 0x80). What follows the
 * UADPFlags octet is entirely conditional on those flags (and on the ExtendedFlags1 / ExtendedFlags2 /
 * GroupHeader / PayloadHeader sub-flag chains): an optional ExtendedFlags1/2, a variable-length
 * PublisherId whose width is chosen by ExtendedFlags1 bits 0..2, an optional DataSetClassId GUID, the
 * GroupHeader, the PayloadHeader, Timestamp/PicoSeconds, promoted fields, the security header and
 * finally the DataSetMessage payload(s) — all little-endian.
 *
 * That layout is too flag-dependent (and cross-message, for chunked/security cases) to slice safely in a
 * single-message codec, so this header takes the deliberate minimal cut mandated by the design: it
 * decomposes only the one always-present UADPFlags octet into its version + four enable bits (each bit
 * of the octet is covered, so it round-trips byte-for-byte), and keeps everything after it verbatim as
 * `body` hex. The body is bounded by the UDP payload length (so Ethernet padding on a short frame is not
 * swallowed) and by the captured bytes, leaving any trailing bytes to the codec's recursion / RawData. A
 * well-formed message round-trips byte-for-byte; per-field UADP dissection (PublisherId, GroupHeader,
 * DataSetMessages, IEC 62541-14 §7.2) is a later enrichment layered on this faithful base.
 */
export class OPCUAPubSub extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (OPCUAPubSub.#schemaCache ??= OPCUAPubSub.#buildSchema())
    }

    /** A single enable bit of the UADPFlags octet at byte 0 (MSB-first bitOffset; 0/1 value). */
    static #fieldFlagBit(name: string, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 1,
            decode: function (this: OPCUAPubSub): void {
                (this.instance as any)[name].setValue(this.readBits(0, 1, bitOffset, 1))
            },
            encode: function (this: OPCUAPubSub): void {
                const node: any = (this.instance as any)[name]
                //Line values are clamped in the closure (never rejected by Ajv) so any decoded value
                //re-encodes; only bit 0 of the supplied value is written into the flag position.
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value < 0) value = 0
                node.setValue(value & 1)
                this.writeBits(0, 1, bitOffset, 1, value & 1)
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'OPC UA PubSub UADP v${version}',
            properties: {
                //UADPFlags low nibble (bits 3..0): the UADPVersion, 1 in the current spec. Kept as a
                //clamped uint (0..15) so a crafted/other version still round-trips rather than being
                //rejected on re-encode.
                version: {
                    type: 'integer',
                    label: 'UADP Version',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: OPCUAPubSub): void {
                        this.instance.version.setValue(this.readBits(0, 1, 4, 4))
                    },
                    encode: function (this: OPCUAPubSub): void {
                        let value: number = this.instance.version.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 15) {
                            this.recordError(this.instance.version.getPath(), 'Maximum value is 15')
                            value = 15
                        }
                        if (value < 0) value = 0
                        this.instance.version.setValue(value)
                        this.writeBits(0, 1, 4, 4, value)
                    }
                },
                //The four UADPFlags enable bits (bits 4..7). Together with the version nibble they cover
                //all 8 bits of the octet, so the UADPFlags byte is reproduced exactly.
                publisherIdEnabled: this.#fieldFlagBit('publisherIdEnabled', 3, 'PublisherId Enabled'),
                groupHeaderEnabled: this.#fieldFlagBit('groupHeaderEnabled', 2, 'GroupHeader Enabled'),
                payloadHeaderEnabled: this.#fieldFlagBit('payloadHeaderEnabled', 1, 'PayloadHeader Enabled'),
                extendedFlags1Enabled: this.#fieldFlagBit('extendedFlags1Enabled', 0, 'ExtendedFlags1 Enabled'),
                //Everything after the UADPFlags octet, kept verbatim. Its layout is fully conditional on
                //the flag chain and is not sliced here. Bounded by the UDP payload length (so trailing
                //Ethernet padding on a short frame is not absorbed) and by the captured bytes.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: OPCUAPubSub): void {
                        const available: number = this.#available()
                        this.instance.body.setValue(available > 1 ? BufferToHex(this.readBytes(1, available - 1)) : '')
                    },
                    encode: function (this: OPCUAPubSub): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(1, HexToBuffer(body))
                    }
                }
            }
        }
    }

    /**
     * Bytes of UADP available in this message: the UDP payload (UDP total length minus the 8-byte UDP
     * header, read from the layer below) clamped to the bytes actually captured. Bounding by the UDP
     * length keeps a short-frame's Ethernet padding out of the body so the frame round-trips exactly.
     */
    #available(): number {
        const remaining: number = this.packet.length - this.startPos
        let available: number = remaining
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpTotalLength: number = prev.instance.length.getValue(0)
            const payload: number = udpTotalLength - 8
            if (payload >= 0 && payload < available) available = payload
        }
        return available
    }

    public readonly id: string = 'opcua-pubsub'

    public readonly name: string = 'OPC UA PubSub'

    public readonly nickname: string = 'OPCUAPubSub'

    public readonly matchKeys: string[] = ['udpport:4840']

    public match(): boolean {
        //OPC UA PubSub UADP rides on UDP port 4840 (opc.tcp binary is the TCP variant and is not this
        //header). No strong content magic — the UADPFlags octet is only weakly distinctive — so the
        //well-known UDP port is the signature. Require at least the single always-present UADPFlags octet.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        return this.packet.length - this.startPos >= 1
    }

    //A leaf header — the flag-conditional UADP body requires cross-field / cross-message parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
