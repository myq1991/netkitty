import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One IPFIX Set: a Set ID and its verbatim hex body (the on-wire Set Length = 4 header octets + body). */
type IpfixSet = {setId: number, setLength: number, body: string}

/**
 * IPFIX — IP Flow Information Export (RFC 7011, also known as NetFlow v10), UDP port 4739. Every IPFIX
 * Message begins with a fixed 16-byte Message Header (all big-endian) — Version (always 10), Length (the
 * total message octet count including this header), Export Time, Sequence Number and Observation Domain
 * ID — followed by one or more Sets. Each Set is a 4-byte header — Set ID (2 = Template Set, 3 = Options
 * Template Set, >= 256 = a Data Set keyed by the Template ID) plus Set Length (the octet count of the
 * whole Set including its 4-byte header) — followed by the Set records.
 *
 * The record layout of a Set is template-driven: a Data Set can only be parsed against the Template Set
 * that defined its Template ID, which is cross-message, session-scoped state. So this single-message
 * codec keeps each Set structured only down to {Set ID, Set Length, verbatim hex body} — byte-perfect —
 * and does not sub-decode the records. The message Length is auto-computed on encode when not supplied,
 * else honored verbatim (a crafted message may lie); each Set Length is honored verbatim, and the Sets
 * walk is bounded by BOTH the message Length and the captured UDP payload, so trailing bytes are left to
 * the codec's recursion / RawData. A well-formed message round-trips byte-for-byte.
 */
export class IPFIX extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (IPFIX.#schemaCache ??= IPFIX.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'IPFIX v${version} len=${length} domain=${observationDomainId}',
            properties: {
                //Version Number (RFC 7011 §3.1): always 10 for IPFIX. Kept as a plain uint16 (clamped in
                //the closure, no hard enum) so a crafted non-10 value still round-trips byte-for-byte.
                version: this.fieldUInt('version', 0, 2, 'Version'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: IPFIX): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: IPFIX): void {
                        //Length counts the whole message = 16-byte header + all Sets. A supplied value is
                        //honored (a crafted message may lie); otherwise a placeholder is written now and
                        //the real total is filled in after every Set has encoded (post-self-encode).
                        const messageLength: number = this.instance.length.getValue(0)
                        if (messageLength) {
                            this.instance.length.setValue(messageLength)
                            this.writeBytes(2, UInt16ToBuffer(messageLength))
                        } else {
                            this.writeBytes(2, UInt16ToBuffer(0))
                            this.instance.length.setValue(0)
                            this.addPostSelfEncodeHandler((): void => {
                                const total: number = this.length < 16 ? 16 : this.length
                                const clamped: number = total > 65535 ? 65535 : total
                                this.instance.length.setValue(clamped)
                                this.writeBytes(2, UInt16ToBuffer(clamped))
                            }, 1)
                        }
                    }
                },
                exportTime: this.fieldUInt('exportTime', 4, 4, 'Export Time'),
                sequenceNumber: this.fieldUInt('sequenceNumber', 8, 4, 'Sequence Number'),
                observationDomainId: this.fieldUInt('observationDomainId', 12, 4, 'Observation Domain ID'),
                sets: {
                    type: 'array',
                    label: 'Sets',
                    items: {
                        type: 'object',
                        label: 'Set',
                        properties: {
                            setId: {type: 'integer', label: 'Set ID', minimum: 0, maximum: 65535},
                            setLength: {type: 'integer', label: 'Set Length', minimum: 0, maximum: 65535},
                            body: {type: 'string', label: 'Body', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: IPFIX): void {
                        //Bound by BOTH the declared message Length AND the bytes actually present, so a
                        //lying Length cannot spawn phantom Sets past the end of the buffer. readBytes clamps
                        //at the buffer end; each Set consumes at least its 4-byte header so the loop always
                        //advances and cannot run forever.
                        const messageLength: number = this.instance.length.getValue(0)
                        const available: number = this.packet.length - this.startPos
                        const end: number = Math.min(messageLength, available)
                        const sets: IpfixSet[] = []
                        let offset: number = 16
                        while (offset + 4 <= end) {
                            const setId: number = BufferToUInt16(this.readBytes(offset, 2))
                            const setLength: number = BufferToUInt16(this.readBytes(offset + 2, 2))
                            offset += 4
                            //Body = Set Length minus the 4-byte Set header, clamped to the remaining bytes
                            //so a lying/short Set Length never reads out of bounds.
                            let bodyLength: number = setLength - 4
                            if (bodyLength < 0) bodyLength = 0
                            if (offset + bodyLength > end) bodyLength = end - offset
                            const body: string = bodyLength > 0 ? BufferToHex(this.readBytes(offset, bodyLength)) : ''
                            offset += bodyLength
                            sets.push({setId: setId, setLength: setLength, body: body})
                        }
                        this.instance.sets.setValue(sets)
                    },
                    encode: function (this: IPFIX): void {
                        const sets: IpfixSet[] | undefined = this.instance.sets.getValue()
                        if (!sets) return
                        let offset: number = 16
                        sets.forEach((set: IpfixSet): void => {
                            const setId: number = set.setId ? set.setId : 0
                            const body: Buffer = HexToBuffer(set.body ? set.body : '')
                            //Set Length counts the 4-byte Set header + body. Honored when supplied (a
                            //crafted Set may lie); else derived from the body.
                            const setLength: number = (set.setLength !== undefined && set.setLength !== null)
                                ? set.setLength
                                : 4 + body.length
                            this.writeBytes(offset, UInt16ToBuffer(setId > 65535 ? 65535 : setId))
                            this.writeBytes(offset + 2, UInt16ToBuffer(setLength > 65535 ? 65535 : setLength))
                            offset += 4
                            if (body.length) {
                                this.writeBytes(offset, body)
                                offset += body.length
                            }
                        })
                    }
                }
            }
        }
    }

    public readonly id: string = 'ipfix'

    public readonly name: string = 'IP Flow Information Export'

    public readonly nickname: string = 'IPFIX'

    public readonly matchKeys: string[] = ['udpport:4739']

    public match(): boolean {
        //IPFIX rides on UDP port 4739. The header carries no strong content magic beyond the Version
        //field, so selection stays port-bucketed (matchKeys) and additionally requires the full 16-byte
        //Message Header and Version == 10 so non-IPFIX 4739 traffic falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.packet.length - this.startPos < 16) return false
        return BufferToUInt16(this.readBytes(0, 2, true)) === 10
    }

    //A leaf header — Set records are template-driven and require cross-message, session-scoped state.
    public readonly demuxProducers: DemuxProducer[] = []

}
