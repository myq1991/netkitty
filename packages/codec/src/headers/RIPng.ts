import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16} from '../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One RIPng Route Table Entry: a 16-byte IPv6 prefix, a Route Tag, a Prefix Length and a Metric. */
type RipngRte = {prefix: string, routeTag: number, prefixLength: number, metric: number}

/**
 * RIPng — RIP for IPv6 (RFC 2080), carried over UDP port 521 (the RIPng process address ff02::9). A
 * RIPng message is a 4-byte fixed header — Command (1 Request, 2 Response), Version (= 1) and a 2-byte
 * reserved field (kept verbatim) — followed by zero or more 20-byte Route Table Entries (RTEs). Each
 * RTE is an IPv6 Prefix (16 bytes), a Route Tag (2 bytes), a Prefix Length (1 byte) and a Metric
 * (1 byte). An RTE with Metric 255 and Prefix Length 0 is a Next Hop RTE (RFC 2080 §2.1.1) carrying the
 * next-hop address for the RTEs that follow it; it is carried structurally like any other RTE.
 *
 * The message has no length field of its own — the RTE array runs to the end of the UDP payload
 * (udp.length - 8), which bounds the walk so retained Ethernet padding / trailing bytes are not
 * absorbed. The IPv6 Prefix is kept verbatim as a lower-case hex string so any prefix (including a
 * zero prefix, or a next-hop address) round-trips byte-for-byte. RIPng is a leaf — nothing rides on it.
 */
export class RIPng extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (RIPng.#schemaCache ??= RIPng.#buildSchema())
    }

    /** The payload length bounded by the UDP datagram (so retained padding/FCS is not absorbed). */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'RIPng cmd=${command} ${rtes.length} RTEs',
            properties: {
                //Fixed 4-byte header: Command (1 Request / 2 Response), Version (= 1), 2-byte reserved.
                command: this.fieldUInt('command', 0, 1, 'Command'),
                version: this.fieldUInt('version', 1, 1, 'Version'),
                //Reserved (2 bytes, must be zero per RFC 2080 but kept verbatim so a non-zero value in a
                //crafted/non-conformant message still round-trips byte-for-byte).
                reserved: this.fieldUInt('reserved', 2, 2, 'Reserved'),
                //Route Table Entries — 20 bytes each, running from offset 4 to the end of the UDP payload.
                rtes: {
                    type: 'array',
                    label: 'Route Table Entries',
                    items: {
                        type: 'object',
                        label: 'RTE',
                        properties: {
                            prefix: {type: 'string', label: 'IPv6 Prefix', contentEncoding: StringContentEncodingEnum.HEX},
                            routeTag: {type: 'integer', label: 'Route Tag', minimum: 0, maximum: 65535},
                            prefixLength: {type: 'integer', label: 'Prefix Length', minimum: 0, maximum: 255},
                            metric: {type: 'integer', label: 'Metric', minimum: 0, maximum: 255}
                        }
                    },
                    decode: function (this: RIPng): void {
                        //No length field: the RTE array runs to the end of the UDP payload, 20 bytes each.
                        //A trailing fragment shorter than 20 bytes (truncation/padding) is not consumed.
                        const end: number = this.#payloadLength()
                        const rtes: RipngRte[] = []
                        let offset: number = 4
                        while (offset + 20 <= end) {
                            rtes.push({
                                prefix: BufferToHex(this.readBytes(offset, 16)),
                                routeTag: BufferToUInt16(this.readBytes(offset + 16, 2)),
                                prefixLength: BufferToUInt8(this.readBytes(offset + 18, 1)),
                                metric: BufferToUInt8(this.readBytes(offset + 19, 1))
                            })
                            offset += 20
                        }
                        this.instance.rtes.setValue(rtes)
                    },
                    encode: function (this: RIPng): void {
                        const rtes: RipngRte[] = this.instance.rtes.getValue([])
                        if (!rtes) return
                        let offset: number = 4
                        for (let i: number = 0; i < rtes.length; i++) {
                            const rte: RipngRte = rtes[i]
                            //The Prefix is a fixed 16 bytes: pad/truncate a crafted value to exactly 16
                            //(32 hex chars) so a malformed input can never shift the following RTEs.
                            const prefix: string = (rte.prefix ? rte.prefix : '').padStart(32, '0').slice(-32)
                            this.writeBytes(offset, HexToBuffer(prefix))
                            this.writeBytes(offset + 16, UInt16ToBuffer(this.#clamp(`rtes[${i}].routeTag`, rte.routeTag, 65535)))
                            this.writeBytes(offset + 18, UInt8ToBuffer(this.#clamp(`rtes[${i}].prefixLength`, rte.prefixLength, 255)))
                            this.writeBytes(offset + 19, UInt8ToBuffer(this.#clamp(`rtes[${i}].metric`, rte.metric, 255)))
                            offset += 20
                        }
                    }
                }
            }
        }
    }

    /** Clamp a crafted RTE field to [0, max], recording an error rather than throwing or wrapping. */
    #clamp(path: string, value: number | undefined, max: number): number {
        let v: number = (value === undefined || value === null) ? 0 : value
        if (v > max) {
            this.recordError(path, `Maximum value is ${max}`)
            v = max
        }
        if (v < 0) {
            this.recordError(path, 'Minimum value is 0')
            v = 0
        }
        return v
    }

    public readonly id: string = 'ripng'

    public readonly name: string = 'RIP for IPv6'

    public readonly nickname: string = 'RIPng'

    public readonly matchKeys: string[] = ['udpport:521']

    public match(): boolean {
        //RIPng rides on UDP port 521. Require the full 4-byte fixed header within the UDP payload and a
        //conformant Command (1 Request / 2 Response) + Version (1) signature, so non-RIPng traffic on
        //port 521 falls through to raw rather than claiming a layer.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.#payloadLength() < 4) return false
        const command: number = BufferToUInt8(this.readBytes(0, 1, true))
        const version: number = BufferToUInt8(this.readBytes(1, 1, true))
        if (command !== 1 && command !== 2) return false
        if (version !== 1) return false
        return true
    }

    //A leaf header — nothing is carried on top of a RIPng message.
    public readonly demuxProducers: DemuxProducer[] = []

}
