import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToUInt8, BufferToUInt16, BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt16ToBuffer, UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {BufferToIPv4} from '../../helper/BufferToIP'
import {IPv4ToBuffer} from '../../helper/IPToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One RIP v2 route table entry: a fixed 20-byte block (RFC 2453 §4). All multi-byte fields are big-endian. */
type RIPRouteEntry = {
    addressFamily: number
    routeTag: number
    ipAddress: string
    subnetMask: string
    nextHop: string
    metric: number
}

//The fixed geometry of a RIP message: a 4-byte header (command, version, reserved) then route entries
//of 20 bytes each, walked to the end of the UDP payload (RFC 2453 caps a packet at 25 entries).
const HEADER_LENGTH: number = 4
const ENTRY_LENGTH: number = 20

/**
 * RIP v2 — Routing Information Protocol version 2 (RFC 2453). Rides UDP, conventionally source and
 * destination port 520 (responses are multicast to 224.0.0.9). All multi-byte fields are big-endian.
 *
 * A message is a 4-byte header — command (1 = request, 2 = response), version (= 2), and a 2-byte
 * reserved field (must be zero) — followed by zero or more 20-byte route table entries. Each entry is
 * addressFamily (2, AF_INET = 2), routeTag (2), ipAddress (4, IPv4), subnetMask (4, IPv4), nextHop
 * (4, IPv4), and metric (4, 1..16 where 16 = infinity).
 *
 * The entry walk is bounded by the bytes actually present in the UDP payload, so a truncated capture can
 * never over-read; any trailing bytes shorter than a full 20-byte entry fall to the raw layer. Entries
 * are carried generically (including RIPv2 authentication entries, whose addressFamily is 0xFFFF and
 * whose 16 bytes of auth data occupy the ipAddress/subnetMask/nextHop/metric slots) so every entry —
 * route or auth — round-trips byte-for-byte; per-entry auth semantics are a later enrichment. This is a
 * leaf header — nothing demuxes off RIP.
 */
export class RIP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (RIP.#schemaCache ??= RIP.#buildSchema())
    }

    /** Bytes available for this RIP message: the frame end, clamped by the UDP payload length. */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    static #entryItemSchema(): ProtocolFieldJSONSchema {
        return {
            type: 'object',
            label: 'Route Entry',
            properties: {
                addressFamily: {type: 'integer', label: 'Address Family', minimum: 0, maximum: 65535},
                routeTag: {type: 'integer', label: 'Route Tag', minimum: 0, maximum: 65535},
                ipAddress: {type: 'string', label: 'IP Address', minLength: 7, maxLength: 15, contentEncoding: StringContentEncodingEnum.IPv4},
                subnetMask: {type: 'string', label: 'Subnet Mask', minLength: 7, maxLength: 15, contentEncoding: StringContentEncodingEnum.IPv4},
                nextHop: {type: 'string', label: 'Next Hop', minLength: 7, maxLength: 15, contentEncoding: StringContentEncodingEnum.IPv4},
                metric: {type: 'integer', label: 'Metric', minimum: 0, maximum: 4294967295}
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'RIPv2 command ${command}',
            properties: {
                command: this.fieldUInt('command', 0, 1, 'Command'),
                version: this.fieldUInt('version', 1, 1, 'Version'),
                reserved: this.fieldUInt('reserved', 2, 2, 'Reserved'),
                entries: {
                    type: 'array',
                    label: 'Route Entries',
                    items: this.#entryItemSchema(),
                    decode: function (this: RIP): void {
                        //Walk fixed 20-byte entries to the end of the UDP payload. The count is bounded by
                        //the captured bytes so a truncated frame never over-reads; a trailing partial entry
                        //(< 20 bytes) is left for the raw layer.
                        const available: number = this.#available()
                        const total: number = available >= HEADER_LENGTH ? Math.floor((available - HEADER_LENGTH) / ENTRY_LENGTH) : 0
                        const entries: RIPRouteEntry[] = []
                        for (let i: number = 0; i < total; i++) {
                            const base: number = HEADER_LENGTH + i * ENTRY_LENGTH
                            entries.push({
                                addressFamily: BufferToUInt16(this.readBytes(base, 2)),
                                routeTag: BufferToUInt16(this.readBytes(base + 2, 2)),
                                ipAddress: BufferToIPv4(this.readBytes(base + 4, 4)),
                                subnetMask: BufferToIPv4(this.readBytes(base + 8, 4)),
                                nextHop: BufferToIPv4(this.readBytes(base + 12, 4)),
                                metric: BufferToUInt32(this.readBytes(base + 16, 4))
                            })
                        }
                        this.instance.entries.setValue(entries)
                    },
                    encode: function (this: RIP): void {
                        const entries: RIPRouteEntry[] | undefined = this.instance.entries.getValue()
                        if (!Array.isArray(entries)) return
                        entries.forEach((entry: RIPRouteEntry, index: number): void => {
                            const base: number = HEADER_LENGTH + index * ENTRY_LENGTH
                            this.writeBytes(base, UInt16ToBuffer(entry.addressFamily ? entry.addressFamily : 0))
                            this.writeBytes(base + 2, UInt16ToBuffer(entry.routeTag ? entry.routeTag : 0))
                            this.writeBytes(base + 4, IPv4ToBuffer(entry.ipAddress ? entry.ipAddress : '0.0.0.0'))
                            this.writeBytes(base + 8, IPv4ToBuffer(entry.subnetMask ? entry.subnetMask : '0.0.0.0'))
                            this.writeBytes(base + 12, IPv4ToBuffer(entry.nextHop ? entry.nextHop : '0.0.0.0'))
                            this.writeBytes(base + 16, UInt32ToBuffer(entry.metric ? entry.metric : 0))
                        })
                    }
                }
            }
        }
    }

    public readonly id: string = 'rip'

    public readonly name: string = 'Routing Information Protocol'

    public readonly nickname: string = 'RIP'

    //Port-defined (udp:520). The command/version bytes are a weak signature, so this stays a plain
    //bucket entry (no heuristicFallback): RIP only when it rides udp:520, and only when the header looks
    //like RIPv2 (version = 2, command request/response). RIPv1 and non-RIP payloads fall to raw.
    public readonly matchKeys: string[] = ['udpport:520']

    public match(): boolean {
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        //Require the whole 4-byte header and the RIPv2 signature: version (=2) and a defined command
        //(1 = request, 2 = response — the only commands RFC 2453 defines).
        if (this.#available() < HEADER_LENGTH) return false
        const command: number = BufferToUInt8(this.packet.subarray(this.startPos, this.startPos + 1))
        const version: number = BufferToUInt8(this.packet.subarray(this.startPos + 1, this.startPos + 2))
        return version === 2 && (command === 1 || command === 2)
    }

    //Leaf header: the route entries are terminal data, nothing demuxes off RIP.
    public readonly demuxProducers: DemuxProducer[] = []

}
