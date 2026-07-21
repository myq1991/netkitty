import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt16} from '../helper/BufferToNumber'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * PTP — the Precision Time Protocol version 2 (IEEE 1588-2008, with 1588-2019 field naming). A
 * sub-microsecond clock-synchronization protocol widely deployed in power-system substations (IEC 61850
 * / IEEE C37.238 power profile) and industrial automation. It is dual-carried: directly over Ethernet
 * with EtherType 0x88F7 (an Ethernet child — no IP), or over UDP/IPv4/6 on the event port 319 and the
 * general port 320.
 *
 * Every PTP message begins with the same 34-byte common header (IEEE 1588-2008 §13.3): a
 * messageType / majorSdoId(transportSpecific) nibble pair, a versionPTP / minorVersionPTP nibble pair,
 * the total messageLength, domainNumber, a minorSdoId(reserved) octet, a 2-byte flagField, an 8-byte
 * correctionField, a 4-byte reserved(messageTypeSpecific) field, the 10-byte sourcePortIdentity
 * (8-byte clockIdentity + 2-byte portNumber), sequenceId, controlField, and the signed
 * logMessageInterval — followed by the message-type-specific body.
 *
 * The per-type body (Sync/Follow_Up timestamps, Announce clock-quality, Delay/Pdelay, Signaling and
 * Management TLVs) is kept verbatim as `body` hex (byte-perfect) and not sub-decoded in this slice. The
 * messageLength is honored verbatim on encode when supplied (a crafted message may lie) else derived
 * from the body; the message is bounded by messageLength and the transport payload, so a min-size
 * Ethernet frame's trailing padding is left to the codec's recursion / RawData. The correctionField is
 * kept verbatim (never recomputed) — a well-formed message round-trips byte-for-byte.
 */
export class PTP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (PTP.#schemaCache ??= PTP.#buildSchema())
    }

    /**
     * Bytes of PTP available in the enclosing transport. Over UDP the datagram length bounds the message
     * (so retained Ethernet padding / a trailing FCS is not absorbed); over raw Ethernet there is no
     * transport length field, so take the rest of the captured frame (messageLength then bounds the body).
     */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpLength: number = prev.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /**
     * Header-relative end offset of the PTP message: the messageLength field, clamped down to the bytes
     * the transport actually made available (#available). Never less than the 34-byte common header, so
     * the body walk is bounded even when a malformed messageLength overstates the message.
     */
    #bodyEnd(): number {
        let end: number = this.instance.messageLength.getValue(0)
        const available: number = this.#available()
        if (available && available < end) end = available
        if (end < 34) end = 34
        return end
    }

    /** A 4-bit nibble within a single octet (bitOffset 0 = the high nibble, MSB-first). */
    static #nibble(name: string, byteOffset: number, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 15,
            decode: function (this: PTP): void {
                (this.instance as any)[name].setValue(this.readBits(byteOffset, 1, bitOffset, 4))
            },
            encode: function (this: PTP): void {
                //writeBits masks the field, so the two nibbles of the same octet never clobber each other.
                this.writeBits(byteOffset, 1, bitOffset, 4, (this.instance as any)[name].getValue(0))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'PTPv2 msgType=${messageType} seq=${sequenceId}',
            properties: {
                //Byte 0 (MSB first): majorSdoId/transportSpecific (high nibble), messageType (low nibble).
                //messageType: 0 Sync, 1 Delay_Req, 2 Pdelay_Req, 3 Pdelay_Resp, 8 Follow_Up, 9 Delay_Resp,
                //0xA Pdelay_Resp_Follow_Up, 0xB Announce, 0xC Signaling, 0xD Management.
                majorSdoId: this.#nibble('majorSdoId', 0, 0, 'Major SDO ID / Transport Specific'),
                messageType: this.#nibble('messageType', 0, 4, 'Message Type'),
                //Byte 1 (MSB first): minorVersionPTP (high nibble, reserved/0 in 1588-2008), versionPTP
                //(low nibble, 2 for PTPv2).
                minorVersionPTP: this.#nibble('minorVersionPTP', 1, 0, 'Minor Version PTP'),
                versionPTP: this.#nibble('versionPTP', 1, 4, 'Version PTP'),
                messageLength: {
                    type: 'integer',
                    label: 'Message Length',
                    minimum: 34,
                    maximum: 65535,
                    decode: function (this: PTP): void {
                        this.instance.messageLength.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: PTP): void {
                        //messageLength counts the whole message = 34-byte header + body. Honored when
                        //supplied (a crafted message may lie); else derived from the body.
                        const provided: number | undefined = this.instance.messageLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 34 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.messageLength.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        this.instance.messageLength.setValue(value)
                        this.writeBytes(2, UInt16ToBuffer(value))
                    }
                },
                domainNumber: this.fieldUInt('domainNumber', 4, 1, 'Domain Number'),
                //minorSdoId (1588-2019) / reserved (1588-2008), byte 5 — kept verbatim for byte-perfect.
                minorSdoId: this.fieldUInt('minorSdoId', 5, 1, 'Minor SDO ID'),
                //flagField (bytes 6-7): alternateMaster/twoStep/unicast/PTP-profile/security/etc. Kept as
                //hex — the per-bit meaning is message-type dependent; a form still round-trips it exactly.
                flags: this.fieldHex('flags', 6, 2, 'Flags'),
                //correctionField (bytes 8-15): signed 64-bit scaled nanoseconds. Kept verbatim (never
                //recomputed), so a captured message round-trips byte-for-byte.
                correctionField: this.fieldHex('correctionField', 8, 8, 'Correction Field'),
                //reserved (bytes 16-19) / messageTypeSpecific in 1588-2019 — kept verbatim.
                reserved: this.fieldHex('reserved', 16, 4, 'Reserved'),
                //sourcePortIdentity (bytes 20-29): the 8-byte clockIdentity + 2-byte portNumber of the
                //originating port.
                sourcePortIdentity: {
                    type: 'object',
                    label: 'Source Port Identity',
                    properties: {
                        clockIdentity: {
                            type: 'string',
                            label: 'Clock Identity',
                            contentEncoding: StringContentEncodingEnum.HEX,
                            decode: function (this: PTP): void {
                                this.instance.sourcePortIdentity.clockIdentity.setValue(BufferToHex(this.readBytes(20, 8)))
                            },
                            encode: function (this: PTP): void {
                                this.writeBytes(20, HexToBuffer(this.instance.sourcePortIdentity.clockIdentity.getValue('0000000000000000')))
                            }
                        },
                        portNumber: {
                            type: 'integer',
                            label: 'Source Port Number',
                            minimum: 0,
                            maximum: 65535,
                            decode: function (this: PTP): void {
                                this.instance.sourcePortIdentity.portNumber.setValue(BufferToUInt16(this.readBytes(28, 2)))
                            },
                            encode: function (this: PTP): void {
                                this.writeBytes(28, UInt16ToBuffer(this.instance.sourcePortIdentity.portNumber.getValue(0)))
                            }
                        }
                    }
                },
                sequenceId: this.fieldUInt('sequenceId', 30, 2, 'Sequence ID'),
                controlField: this.fieldUInt('controlField', 32, 1, 'Control Field'),
                logMessageInterval: this.fieldInt8('logMessageInterval', 33, 'Log Message Interval'),
                //The message-type-specific body after the 34-byte header, kept verbatim. Bounded by the
                //messageLength (the message ends at offset messageLength) and the transport payload, so
                //Ethernet padding / a pipelined message is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: PTP): void {
                        const end: number = this.#bodyEnd()
                        this.instance.body.setValue(end > 34 ? BufferToHex(this.readBytes(34, end - 34)) : '')
                    },
                    encode: function (this: PTP): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(34, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'ptp'

    public readonly name: string = 'Precision Time Protocol'

    public readonly nickname: string = 'PTP'

    public readonly matchKeys: string[] = ['ethertype:88f7', 'udpport:319', 'udpport:320']

    public match(): boolean {
        //PTP is dual-carried: directly over Ethernet (EtherType 0x88F7) or over UDP on the event port
        //319 / general port 320 (accept src too, to catch responses). Require the full 34-byte common
        //header within the transport payload.
        if (!this.prevCodecModule) return false
        const prev: any = this.prevCodecModule
        if (prev.id === 'udp') {
            const dstport: number = prev.instance.dstport.getValue(0)
            const srcport: number = prev.instance.srcport.getValue(0)
            if (dstport !== 319 && dstport !== 320 && srcport !== 319 && srcport !== 320) return false
            return this.#available() >= 34
        }
        //Ethernet (or a VLAN/HSR parent) child selected by EtherType 0x88F7 (a lowercase 4-hex string).
        if (prev.instance.etherType.getValue() !== '88f7') return false
        return this.packet.length - this.startPos >= 34
    }

    //A leaf header — the per-message-type body (timestamps, Announce clock-quality, Signaling/Management
    //TLVs) is kept verbatim and sub-decoding is deferred to a later slice.
    public readonly demuxProducers: DemuxProducer[] = []

}
