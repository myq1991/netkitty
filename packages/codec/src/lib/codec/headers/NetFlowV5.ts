import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToUInt8, BufferToUInt16, BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt8ToBuffer, UInt16ToBuffer, UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {BufferToIPv4} from '../../helper/BufferToIP'
import {IPv4ToBuffer} from '../../helper/IPToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One NetFlow v5 flow record: a fixed 48-byte block describing a single flow. */
type NetFlowV5Record = {
    srcAddr: string
    dstAddr: string
    nextHop: string
    input: number
    output: number
    dPkts: number
    dOctets: number
    first: number
    last: number
    srcPort: number
    dstPort: number
    pad1: number
    tcpFlags: number
    prot: number
    tos: number
    srcAs: number
    dstAs: number
    srcMask: number
    dstMask: number
    pad2: number
}

//The fixed geometry of a NetFlow v5 export: a 24-byte header, then `count` flow records of 48 bytes.
const HEADER_LENGTH: number = 24
const RECORD_LENGTH: number = 48

/**
 * NetFlow v5 — Cisco's fixed-format flow export (there is no formal RFC; the record layout is Cisco's
 * published v5 format). Rides UDP, conventionally destination port 2055 (also seen on 9995/9996). All
 * fields are big-endian.
 *
 * A packet is a 24-byte header — version(=5), count (number of flow records), sysUptime, unixSecs,
 * unixNsecs, flowSequence, engineType, engineId, samplingInterval — followed by `count` flow records
 * of 48 bytes each (srcAddr/dstAddr/nextHop, input/output ifIndex, packet/octet counts, flow start/end
 * uptimes, ports, TCP flags, protocol, ToS, AS numbers, prefix masks, and two padding fields).
 *
 * The record walk is bounded by BOTH `count` and the bytes actually captured, so a lying count in a
 * truncated capture can never over-read; any trailing bytes beyond 24 + count*48 fall to the raw layer.
 * `count` is honored when supplied (so a malformed count round-trips byte-for-byte) and derived from
 * records.length only when absent (crafting). This is a leaf header — nothing demuxes off NetFlow.
 */
export class NetFlowV5 extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (NetFlowV5.#schemaCache ??= NetFlowV5.#buildSchema())
    }

    /** Bytes available for this NetFlow message: the frame end, clamped by the UDP payload length. */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    static #recordItemSchema(): ProtocolFieldJSONSchema {
        return {
            type: 'object',
            label: 'Flow Record',
            properties: {
                srcAddr: {type: 'string', label: 'Source Address', minLength: 7, maxLength: 15, contentEncoding: StringContentEncodingEnum.IPv4},
                dstAddr: {type: 'string', label: 'Destination Address', minLength: 7, maxLength: 15, contentEncoding: StringContentEncodingEnum.IPv4},
                nextHop: {type: 'string', label: 'Next Hop', minLength: 7, maxLength: 15, contentEncoding: StringContentEncodingEnum.IPv4},
                input: {type: 'integer', label: 'Input SNMP ifIndex', minimum: 0, maximum: 65535},
                output: {type: 'integer', label: 'Output SNMP ifIndex', minimum: 0, maximum: 65535},
                dPkts: {type: 'integer', label: 'Packets', minimum: 0, maximum: 4294967295},
                dOctets: {type: 'integer', label: 'Octets', minimum: 0, maximum: 4294967295},
                first: {type: 'integer', label: 'Flow Start SysUptime', minimum: 0, maximum: 4294967295},
                last: {type: 'integer', label: 'Flow End SysUptime', minimum: 0, maximum: 4294967295},
                srcPort: {type: 'integer', label: 'Source Port', minimum: 0, maximum: 65535},
                dstPort: {type: 'integer', label: 'Destination Port', minimum: 0, maximum: 65535},
                pad1: {type: 'integer', label: 'Pad 1', minimum: 0, maximum: 255},
                tcpFlags: {type: 'integer', label: 'TCP Flags', minimum: 0, maximum: 255},
                prot: {type: 'integer', label: 'Protocol', minimum: 0, maximum: 255},
                tos: {type: 'integer', label: 'Type of Service', minimum: 0, maximum: 255},
                srcAs: {type: 'integer', label: 'Source AS', minimum: 0, maximum: 65535},
                dstAs: {type: 'integer', label: 'Destination AS', minimum: 0, maximum: 65535},
                srcMask: {type: 'integer', label: 'Source Mask', minimum: 0, maximum: 255},
                dstMask: {type: 'integer', label: 'Destination Mask', minimum: 0, maximum: 255},
                pad2: {type: 'integer', label: 'Pad 2', minimum: 0, maximum: 65535}
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'NetFlow v5 ${count} flows',
            properties: {
                version: this.fieldUInt('version', 0, 2, 'Version'),
                count: {
                    type: 'integer',
                    label: 'Count',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: NetFlowV5): void {
                        this.instance.count.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: NetFlowV5): void {
                        //Honor an explicitly-set count (even a lying one — so a malformed capture still
                        //round-trips byte-for-byte); derive from the record array only when absent (crafting).
                        let count: number | undefined = this.instance.count.getValue()
                        if (count === undefined || count === null) {
                            const records: NetFlowV5Record[] | undefined = this.instance.records.getValue()
                            count = Array.isArray(records) ? records.length : 0
                        }
                        if (count > 65535) {
                            this.recordError(this.instance.count.getPath(), 'Maximum value is 65535')
                            count = 65535
                        }
                        if (count < 0) {
                            this.recordError(this.instance.count.getPath(), 'Minimum value is 0')
                            count = 0
                        }
                        this.instance.count.setValue(count)
                        this.writeBytes(2, UInt16ToBuffer(count))
                    }
                },
                sysUptime: this.fieldUInt('sysUptime', 4, 4, 'System Uptime'),
                unixSecs: this.fieldUInt('unixSecs', 8, 4, 'Unix Seconds'),
                unixNsecs: this.fieldUInt('unixNsecs', 12, 4, 'Unix Nanoseconds'),
                flowSequence: this.fieldUInt('flowSequence', 16, 4, 'Flow Sequence'),
                engineType: this.fieldUInt('engineType', 20, 1, 'Engine Type'),
                engineId: this.fieldUInt('engineId', 21, 1, 'Engine ID'),
                samplingInterval: this.fieldUInt('samplingInterval', 22, 2, 'Sampling Interval'),
                records: {
                    type: 'array',
                    label: 'Flow Records',
                    items: this.#recordItemSchema(),
                    decode: function (this: NetFlowV5): void {
                        //Bound the walk by BOTH the declared count and the captured bytes: a lying count in
                        //a truncated frame must never read past the buffer. Each record is a fixed 48 bytes.
                        const count: number = this.instance.count.getValue(0)
                        const available: number = this.#available()
                        const maxByBytes: number = available >= HEADER_LENGTH ? Math.floor((available - HEADER_LENGTH) / RECORD_LENGTH) : 0
                        const total: number = Math.min(count, maxByBytes)
                        const records: NetFlowV5Record[] = []
                        for (let i: number = 0; i < total; i++) {
                            const base: number = HEADER_LENGTH + i * RECORD_LENGTH
                            records.push({
                                srcAddr: BufferToIPv4(this.readBytes(base, 4)),
                                dstAddr: BufferToIPv4(this.readBytes(base + 4, 4)),
                                nextHop: BufferToIPv4(this.readBytes(base + 8, 4)),
                                input: BufferToUInt16(this.readBytes(base + 12, 2)),
                                output: BufferToUInt16(this.readBytes(base + 14, 2)),
                                dPkts: BufferToUInt32(this.readBytes(base + 16, 4)),
                                dOctets: BufferToUInt32(this.readBytes(base + 20, 4)),
                                first: BufferToUInt32(this.readBytes(base + 24, 4)),
                                last: BufferToUInt32(this.readBytes(base + 28, 4)),
                                srcPort: BufferToUInt16(this.readBytes(base + 32, 2)),
                                dstPort: BufferToUInt16(this.readBytes(base + 34, 2)),
                                pad1: BufferToUInt8(this.readBytes(base + 36, 1)),
                                tcpFlags: BufferToUInt8(this.readBytes(base + 37, 1)),
                                prot: BufferToUInt8(this.readBytes(base + 38, 1)),
                                tos: BufferToUInt8(this.readBytes(base + 39, 1)),
                                srcAs: BufferToUInt16(this.readBytes(base + 40, 2)),
                                dstAs: BufferToUInt16(this.readBytes(base + 42, 2)),
                                srcMask: BufferToUInt8(this.readBytes(base + 44, 1)),
                                dstMask: BufferToUInt8(this.readBytes(base + 45, 1)),
                                pad2: BufferToUInt16(this.readBytes(base + 46, 2))
                            })
                        }
                        this.instance.records.setValue(records)
                    },
                    encode: function (this: NetFlowV5): void {
                        const records: NetFlowV5Record[] | undefined = this.instance.records.getValue()
                        if (!Array.isArray(records)) return
                        records.forEach((record: NetFlowV5Record, index: number): void => {
                            const base: number = HEADER_LENGTH + index * RECORD_LENGTH
                            this.writeBytes(base, IPv4ToBuffer(record.srcAddr ? record.srcAddr : '0.0.0.0'))
                            this.writeBytes(base + 4, IPv4ToBuffer(record.dstAddr ? record.dstAddr : '0.0.0.0'))
                            this.writeBytes(base + 8, IPv4ToBuffer(record.nextHop ? record.nextHop : '0.0.0.0'))
                            this.writeBytes(base + 12, UInt16ToBuffer(record.input ? record.input : 0))
                            this.writeBytes(base + 14, UInt16ToBuffer(record.output ? record.output : 0))
                            this.writeBytes(base + 16, UInt32ToBuffer(record.dPkts ? record.dPkts : 0))
                            this.writeBytes(base + 20, UInt32ToBuffer(record.dOctets ? record.dOctets : 0))
                            this.writeBytes(base + 24, UInt32ToBuffer(record.first ? record.first : 0))
                            this.writeBytes(base + 28, UInt32ToBuffer(record.last ? record.last : 0))
                            this.writeBytes(base + 32, UInt16ToBuffer(record.srcPort ? record.srcPort : 0))
                            this.writeBytes(base + 34, UInt16ToBuffer(record.dstPort ? record.dstPort : 0))
                            this.writeBytes(base + 36, UInt8ToBuffer(record.pad1 ? record.pad1 : 0))
                            this.writeBytes(base + 37, UInt8ToBuffer(record.tcpFlags ? record.tcpFlags : 0))
                            this.writeBytes(base + 38, UInt8ToBuffer(record.prot ? record.prot : 0))
                            this.writeBytes(base + 39, UInt8ToBuffer(record.tos ? record.tos : 0))
                            this.writeBytes(base + 40, UInt16ToBuffer(record.srcAs ? record.srcAs : 0))
                            this.writeBytes(base + 42, UInt16ToBuffer(record.dstAs ? record.dstAs : 0))
                            this.writeBytes(base + 44, UInt8ToBuffer(record.srcMask ? record.srcMask : 0))
                            this.writeBytes(base + 45, UInt8ToBuffer(record.dstMask ? record.dstMask : 0))
                            this.writeBytes(base + 46, UInt16ToBuffer(record.pad2 ? record.pad2 : 0))
                        })
                    }
                }
            }
        }
    }

    public readonly id: string = 'netflow5'

    public readonly name: string = 'NetFlow v5'

    public readonly nickname: string = 'NetFlow v5'

    //Port-defined (udp:2055, and the commonly-used 9995/9996). NetFlow v5 does carry a reliable content
    //signature — the first two bytes are the version (=5) — but that alone is weak, so it stays a plain
    //bucket entry (no heuristicFallback): NetFlow v5 only when it rides one of its known UDP ports.
    public readonly matchKeys: string[] = ['udpport:2055', 'udpport:9995', 'udpport:9996']

    public match(): boolean {
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        //Require the whole 24-byte header within the payload and the version signature (=5).
        if (this.#available() < HEADER_LENGTH) return false
        const version: number = BufferToUInt16(this.packet.subarray(this.startPos, this.startPos + 2))
        return version === 5
    }

    //Leaf header: the flow records are terminal data, nothing demuxes off NetFlow.
    public readonly demuxProducers: DemuxProducer[] = []

}
