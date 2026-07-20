import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One MPLS label stack entry: 20-bit Label, 3-bit Traffic Class, 1-bit Bottom-of-Stack, 8-bit TTL. */
type MplsEntry = {label: number, tc: number, s: number, ttl: number}

/**
 * MPLS — Multiprotocol Label Switching (RFC 3032), carried directly in an Ethernet II frame with
 * EtherType 0x8847 (unicast) or 0x8848 (multicast) — an Ethernet child, no IP/UDP below it. The MPLS
 * shim is a label stack: a sequence of 4-byte entries, each packing a 20-bit Label, a 3-bit Traffic
 * Class / Experimental field (TC/EXP), a 1-bit Bottom-of-Stack flag (S), and an 8-bit Time To Live
 * (TTL). The stack repeats until an entry with S=1 (the bottom of stack); the encapsulated packet
 * (typically IPv4/IPv6, dispatched by the first payload nibble) follows immediately after it.
 *
 * This codec is the label-stack leaf: it decodes the stack (each entry's structured label/tc/s/ttl)
 * up to and including the S=1 entry, then keeps the encapsulated packet after it as an opaque `payload`
 * hex field so MPLS is a self-contained byte-perfect leaf. (It deliberately consumes the payload rather
 * than leaving it to the codec's recursion: with IPv4/IPv6.match unchanged the inner IP would not fall
 * to RawData but be claimed by the greedy EthernetII content heuristic, which emits an un-re-encodable
 * layer for a short trailer. Owning the bytes keeps decode→encode from ever throwing.) Each entry and
 * the payload are re-emitted verbatim, so a well-formed shim round-trips byte-for-byte. Structured inner
 * IPv4/IPv6 recursion is a serial follow-up (IPv4/IPv6.match must learn an 'mpls' parent branch
 * dispatching on the first payload nibble, at which point `payload` becomes real child layers).
 */
export class MPLS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (MPLS.#schemaCache ??= MPLS.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'MPLS ${entries.length} labels',
            properties: {
                entries: {
                    type: 'array',
                    label: 'Label Stack',
                    items: {
                        type: 'object',
                        label: 'Label Stack Entry',
                        properties: {
                            label: {type: 'integer', label: 'Label', minimum: 0, maximum: 1048575},
                            tc: {type: 'integer', label: 'Traffic Class', minimum: 0, maximum: 7},
                            s: {type: 'integer', label: 'Bottom of Stack', minimum: 0, maximum: 1},
                            ttl: {type: 'integer', label: 'Time To Live', minimum: 0, maximum: 255}
                        }
                    },
                    decode: function (this: MPLS): void {
                        //The label stack has no length field of its own — it runs until an entry with S=1
                        //(bottom of stack). Bound the walk by the remaining frame bytes, reading each
                        //4-byte entry as label(20)+tc(3)+s(1)+ttl(8), MSB-first. A truncated final entry
                        //(fewer than 4 bytes left) stops the walk without being consumed.
                        const available: number = this.packet.length - this.startPos
                        const entries: MplsEntry[] = []
                        let offset: number = 0
                        while (offset + 4 <= available) {
                            const label: number = this.readBits(offset, 4, 0, 20)
                            const tc: number = this.readBits(offset, 4, 20, 3)
                            const s: number = this.readBits(offset, 4, 23, 1)
                            const ttl: number = this.readBits(offset, 4, 24, 8)
                            entries.push({label: label, tc: tc, s: s, ttl: ttl})
                            offset += 4
                            //Bottom of stack — the encapsulated payload follows, left to the codec's
                            //recursion (do not read into it).
                            if (s === 1) break
                        }
                        this.instance.entries.setValue(entries)
                    },
                    encode: function (this: MPLS): void {
                        //Faithful executor: emit each supplied entry exactly as given (S and TC kept
                        //verbatim), even a stack that never sets S=1 — a crafted frame may be malformed.
                        const entries: MplsEntry[] = this.instance.entries.getValue([])
                        let offset: number = 0
                        if (entries) {
                            for (let i: number = 0; i < entries.length; i++) {
                                const entry: MplsEntry = entries[i] ? entries[i] : ({} as MplsEntry)
                                let label: number = entry.label ? entry.label : 0
                                //Label is a 20-bit field. A larger value cannot be represented; clamp and
                                //record the error rather than letting writeBits wrap it modulo 2^20 (which
                                //would silently corrupt the label).
                                if (label > 1048575) {
                                    this.recordError(`entries[${i}].label`, 'Maximum label is 1048575')
                                    label = 1048575
                                }
                                if (label < 0) {
                                    this.recordError(`entries[${i}].label`, 'Minimum label is 0')
                                    label = 0
                                }
                                //writeBits masks each field to its width, so label/tc/s/ttl never clobber.
                                this.writeBits(offset, 4, 0, 20, label)
                                this.writeBits(offset, 4, 20, 3, entry.tc ? entry.tc : 0)
                                this.writeBits(offset, 4, 23, 1, entry.s ? entry.s : 0)
                                this.writeBits(offset, 4, 24, 8, entry.ttl ? entry.ttl : 0)
                                offset += 4
                            }
                        }
                    }
                },
                //The encapsulated packet after the label stack, kept as opaque hex so MPLS owns every
                //byte and is a self-contained byte-perfect leaf (see the class doc for why it is not left
                //to the codec's recursion). It starts right after the stack — entries.length × 4 bytes.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: MPLS): void {
                        const stackBytes: number = (this.instance.entries.getValue([]) || []).length * 4
                        const available: number = this.packet.length - this.startPos
                        const payloadLength: number = available - stackBytes
                        this.instance.payload.setValue(payloadLength > 0 ? BufferToHex(this.readBytes(stackBytes, payloadLength)) : '')
                    },
                    encode: function (this: MPLS): void {
                        const stackBytes: number = (this.instance.entries.getValue([]) || []).length * 4
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(stackBytes, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'mpls'

    public readonly name: string = 'Multiprotocol Label Switching'

    public readonly nickname: string = 'MPLS'

    public readonly matchKeys: string[] = ['ethertype:8847', 'ethertype:8848']

    public match(): boolean {
        //An Ethernet child selected by EtherType 0x8847 (unicast) or 0x8848 (multicast), stored as a
        //lowercase 4-hex string on the parent. Require at least one 4-byte label stack entry.
        if (!this.prevCodecModule) return false
        const etherType: string = this.prevCodecModule.instance.etherType.getValue()
        if (etherType !== '8847' && etherType !== '8848') return false
        return this.packet.length - this.startPos >= 4
    }

    //A leaf header for this slice: the encapsulated packet is left to the codec's recursion (inner IP
    //recursion is a serial follow-up — see the class doc), so nothing demuxes off MPLS yet.
    public readonly demuxProducers: DemuxProducer[] = []

}
