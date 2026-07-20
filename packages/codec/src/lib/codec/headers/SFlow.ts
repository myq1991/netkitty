import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {BufferToIPv4} from '../../helper/BufferToIP'
import {IPv4ToBuffer} from '../../helper/IPToBuffer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One sFlow sample record: a type/length tag plus its opaque body kept verbatim as hex. */
type SFlowSample = {
    sampleType: number
    sampleLength: number
    sampleData: string
}

//Fixed geometry of an sFlow v5 datagram. The head up to (and including) agentAddressType is 8 bytes;
//the agent address is 4 bytes (IPv4) or 16 bytes (IPv6); then four 4-byte fields (subAgentId,
//sequenceNumber, sysUptime, numSamples) precede the sample list. Each sample carries an 8-byte tag
//(sampleType + sampleLength) followed by sampleLength opaque bytes.
const AGENT_ADDRESS_OFFSET: number = 8
const IPV4_ADDRESS_LENGTH: number = 4
const IPV6_ADDRESS_LENGTH: number = 16
const AGENT_ADDRESS_TYPE_IPV6: number = 2
const TRAILER_FIELDS_LENGTH: number = 16
const SAMPLE_TAG_LENGTH: number = 8

/**
 * sFlow v5 — sampled flow monitoring export (sflow.org v5 spec; historically RFC 3176 for v4). Rides
 * UDP, conventionally destination port 6343. All fields are big-endian.
 *
 * The datagram header is: version (=5), agentAddressType (1 = IPv4, 2 = IPv6), the agent address
 * (4 bytes for IPv4, 16 bytes for IPv6 — the ONLY variable-length part of the fixed header, and it
 * shifts every downstream offset), subAgentId, sequenceNumber, sysUptime, and numSamples. Then
 * `numSamples` sample records follow, each a 4-byte sampleType (enterprise << 12 | format), a 4-byte
 * sampleLength, and sampleLength opaque bytes carried verbatim as hex (structuring the per-format
 * flow/counter records is a later slice).
 *
 * The sample walk is bounded by BOTH `numSamples` and the bytes actually captured, so a lying
 * numSamples in a truncated frame can never over-read; any trailing bytes fall to the raw layer.
 * numSamples is honored when supplied (so a malformed datagram round-trips byte-for-byte) and derived
 * from samples.length only when absent (crafting). This is a leaf header — nothing demuxes off sFlow.
 */
export class SFlow extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SFlow.#schemaCache ??= SFlow.#buildSchema())
    }

    /** Length in bytes of the agent address, driven by the decoded agentAddressType (IPv6 → 16, else 4). */
    #agentAddressLength(): number {
        return this.instance.agentAddressType.getValue(1) === AGENT_ADDRESS_TYPE_IPV6 ? IPV6_ADDRESS_LENGTH : IPV4_ADDRESS_LENGTH
    }

    /** Offset of subAgentId — the first field after the variable-length agent address. */
    #subAgentIdOffset(): number {
        return AGENT_ADDRESS_OFFSET + this.#agentAddressLength()
    }

    /** Offset of the first sample record: the whole fixed header (address-type dependent). */
    #headerLength(): number {
        return this.#subAgentIdOffset() + TRAILER_FIELDS_LENGTH
    }

    /** Bytes available for this sFlow datagram: the frame end, clamped by the UDP payload length. */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /** A big-endian uint32 field at a dynamic (address-type driven) offset produced by `offset`. */
    static #uint32At(name: string, offset: (this: SFlow) => number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 4294967295,
            decode: function (this: SFlow): void {
                (this.instance as any)[name].setValue(BufferToUInt32(this.readBytes(offset.call(this), 4)))
            },
            encode: function (this: SFlow): void {
                const node: any = (this.instance as any)[name]
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
                this.writeBytes(offset.call(this), UInt32ToBuffer(value))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'sFlow ${numSamples} samples',
            properties: {
                version: SFlow.fieldUInt('version', 0, 4, 'Version'),
                agentAddressType: SFlow.fieldUInt('agentAddressType', 4, 4, 'Agent Address Type'),
                //The only variable-length field of the fixed header: 4 bytes as a dotted quad for IPv4
                //(type 1), 16 bytes kept verbatim as hex for IPv6 (type 2). Its length shifts every
                //downstream offset, so all trailing fields compute their offset from #subAgentIdOffset().
                agentAddress: {
                    type: 'string',
                    label: 'Agent Address',
                    decode: function (this: SFlow): void {
                        const length: number = this.instance.agentAddressType.getValue(1) === AGENT_ADDRESS_TYPE_IPV6 ? IPV6_ADDRESS_LENGTH : IPV4_ADDRESS_LENGTH
                        const buffer: Buffer = this.readBytes(AGENT_ADDRESS_OFFSET, length)
                        this.instance.agentAddress.setValue(length === IPV6_ADDRESS_LENGTH ? BufferToHex(buffer) : BufferToIPv4(buffer))
                    },
                    encode: function (this: SFlow): void {
                        const node: any = this.instance.agentAddress
                        if (this.instance.agentAddressType.getValue(1) === AGENT_ADDRESS_TYPE_IPV6) {
                            const value: string = node.getValue('00'.repeat(IPV6_ADDRESS_LENGTH), (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            node.setValue(value)
                            this.writeBytes(AGENT_ADDRESS_OFFSET, HexToBuffer(value))
                        } else {
                            const value: string = node.getValue('0.0.0.0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            node.setValue(value)
                            this.writeBytes(AGENT_ADDRESS_OFFSET, IPv4ToBuffer(value))
                        }
                    }
                },
                subAgentId: SFlow.#uint32At('subAgentId', function (this: SFlow): number {
                    return this.#subAgentIdOffset()
                }, 'Sub Agent ID'),
                sequenceNumber: SFlow.#uint32At('sequenceNumber', function (this: SFlow): number {
                    return this.#subAgentIdOffset() + 4
                }, 'Sequence Number'),
                sysUptime: SFlow.#uint32At('sysUptime', function (this: SFlow): number {
                    return this.#subAgentIdOffset() + 8
                }, 'System Uptime'),
                numSamples: {
                    type: 'integer',
                    label: 'Number of Samples',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: SFlow): void {
                        this.instance.numSamples.setValue(BufferToUInt32(this.readBytes(this.#subAgentIdOffset() + 12, 4)))
                    },
                    encode: function (this: SFlow): void {
                        //Honor an explicitly-set numSamples (even a lying one — so a malformed capture still
                        //round-trips byte-for-byte); derive from the sample array only when absent (crafting).
                        let numSamples: number | undefined = this.instance.numSamples.getValue()
                        if (numSamples === undefined || numSamples === null) {
                            const samples: SFlowSample[] | undefined = this.instance.samples.getValue()
                            numSamples = Array.isArray(samples) ? samples.length : 0
                        }
                        if (numSamples > 4294967295) {
                            this.recordError(this.instance.numSamples.getPath(), 'Maximum value is 4294967295')
                            numSamples = 4294967295
                        }
                        if (numSamples < 0) {
                            this.recordError(this.instance.numSamples.getPath(), 'Minimum value is 0')
                            numSamples = 0
                        }
                        this.instance.numSamples.setValue(numSamples)
                        this.writeBytes(this.#subAgentIdOffset() + 12, UInt32ToBuffer(numSamples))
                    }
                },
                samples: {
                    type: 'array',
                    label: 'Samples',
                    items: {
                        type: 'object',
                        label: 'Sample',
                        properties: {
                            sampleType: {type: 'integer', label: 'Sample Type', minimum: 0, maximum: 4294967295},
                            sampleLength: {type: 'integer', label: 'Sample Length', minimum: 0, maximum: 4294967295},
                            sampleData: {type: 'string', label: 'Sample Data', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: SFlow): void {
                        //Bound the walk by BOTH the declared numSamples and the captured bytes: a lying
                        //numSamples in a truncated frame must never read past the buffer. Each record is an
                        //8-byte tag (type + length) followed by `sampleLength` opaque bytes.
                        const numSamples: number = this.instance.numSamples.getValue(0)
                        const end: number = this.#available()
                        const samples: SFlowSample[] = []
                        let offset: number = this.#headerLength()
                        for (let i: number = 0; i < numSamples; i++) {
                            if (offset + SAMPLE_TAG_LENGTH > end) break
                            const sampleType: number = BufferToUInt32(this.readBytes(offset, 4, true))
                            const sampleLength: number = BufferToUInt32(this.readBytes(offset + 4, 4, true))
                            if (offset + SAMPLE_TAG_LENGTH + sampleLength > end) break
                            this.readBytes(offset, SAMPLE_TAG_LENGTH + sampleLength)
                            const sampleData: string = sampleLength > 0 ? BufferToHex(this.packet.subarray(this.getPacketOffset(offset + SAMPLE_TAG_LENGTH), this.getPacketOffset(offset + SAMPLE_TAG_LENGTH + sampleLength))) : ''
                            samples.push({sampleType: sampleType, sampleLength: sampleLength, sampleData: sampleData})
                            offset += SAMPLE_TAG_LENGTH + sampleLength
                        }
                        this.instance.samples.setValue(samples)
                    },
                    encode: function (this: SFlow): void {
                        const samples: SFlowSample[] | undefined = this.instance.samples.getValue()
                        if (!Array.isArray(samples)) return
                        let offset: number = this.#headerLength()
                        for (const sample of samples) {
                            const body: Buffer = HexToBuffer(sample.sampleData ? sample.sampleData : '')
                            //Honor an explicit sampleLength (byte-perfect for decoded frames), else derive
                            //it from the opaque body.
                            const sampleLength: number = (sample.sampleLength !== undefined && sample.sampleLength !== null)
                                ? sample.sampleLength
                                : body.length
                            this.writeBytes(offset, UInt32ToBuffer(sample.sampleType ? sample.sampleType : 0))
                            this.writeBytes(offset + 4, UInt32ToBuffer(sampleLength))
                            offset += SAMPLE_TAG_LENGTH
                            if (body.length) {
                                this.writeBytes(offset, body)
                                offset += body.length
                            }
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'sflow'

    public readonly name: string = 'sFlow v5'

    public readonly nickname: string = 'sFlow'

    //Port-defined (udp:6343). sFlow does carry a content signature — the first four bytes are the
    //version (=5) — but that alone is weak, so it stays a plain bucket entry (no heuristicFallback):
    //sFlow v5 only when it rides its well-known UDP port.
    public readonly matchKeys: string[] = ['udpport:6343']

    public match(): boolean {
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        //Require the smallest possible datagram (IPv4-agent header = 28 bytes) and the version
        //signature (=5). Anything else on port 6343 falls through to raw.
        if (this.#available() < 28) return false
        const version: number = BufferToUInt32(this.packet.subarray(this.startPos, this.startPos + 4))
        return version === 5
    }

    //Leaf header: the sample records are terminal opaque data, nothing demuxes off sFlow.
    public readonly demuxProducers: DemuxProducer[] = []

}
