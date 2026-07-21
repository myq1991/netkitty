import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Ethernet POWERLINK (EPL, EPSG DS 301 / IEC 61784-2 CPF 13), a real-time industrial Ethernet protocol
 * carried directly in an Ethernet II frame with EtherType 0x88AB (an Ethernet child — no IP/UDP). Every
 * EPL basic frame begins with a fixed 3-byte common header: a 1-byte MessageType octet (bit 7 Reserved,
 * bits 6..0 the 7-bit message type), a 1-byte Destination node id, and a 1-byte Source node id. The
 * message types are SoC = 1 (Start of Cycle), PReq = 3 (Poll Request), PRes = 4 (Poll Response),
 * SoA = 5 (Start of Asynchronous), ASnd = 6 (Asynchronous Send). The type-specific body follows.
 *
 * EPL has no length field of its own — a basic frame runs to the end of the Ethernet frame (short frames
 * are Ethernet-padded to the 60-byte minimum). The per-type body layouts (SoC NetTime/RelativeTime, PReq/
 * PRes flags+PDO payload, SoA service request, ASnd service data) differ and several carry variable
 * mapped-PDO data, so this minimal slice decodes only the 3-byte common header structurally and keeps the
 * remainder — body plus any trailing Ethernet padding — verbatim as `payload` hex (byte-perfect, a
 * self-contained leaf, so nothing depends on RawData). A well-formed frame round-trips byte-for-byte.
 */
export class POWERLINK extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (POWERLINK.#schemaCache ??= POWERLINK.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'POWERLINK mtype=${messageType} ${source}->${destination}',
            properties: {
                //MessageType octet (byte 0): the high bit (0x80) is Reserved, kept verbatim so a frame that
                //sets it still round-trips; the low 7 bits (0x7F, epl.mtyp) carry the message type.
                reserved: {
                    type: 'integer',
                    label: 'Reserved',
                    minimum: 0,
                    maximum: 1,
                    hidden: true,
                    decode: function (this: POWERLINK): void {
                        this.instance.reserved.setValue(this.readBits(0, 1, 0, 1))
                    },
                    encode: function (this: POWERLINK): void {
                        this.writeBits(0, 1, 0, 1, this.instance.reserved.getValue(0))
                    }
                },
                messageType: {
                    type: 'integer',
                    label: 'Message Type',
                    minimum: 0,
                    maximum: 127,
                    decode: function (this: POWERLINK): void {
                        this.instance.messageType.setValue(this.readBits(0, 1, 1, 7))
                    },
                    encode: function (this: POWERLINK): void {
                        const node: any = this.instance.messageType
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        //A 7-bit field cannot represent a value above 127 — clamp (recording the error)
                        //rather than let it wrap into the Reserved bit and corrupt byte 0.
                        if (value > 127) {
                            this.recordError(node.getPath(), 'Maximum value is 127')
                            value = 127
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBits(0, 1, 1, 7, value)
                    }
                },
                destination: this.fieldUInt('destination', 1, 1, 'Destination Node'),
                source: this.fieldUInt('source', 2, 1, 'Source Node'),
                //The type-specific body plus any trailing Ethernet padding, kept verbatim. EPL has no
                //length field, so — like LLDP — the frame runs to its end; the whole remainder after the
                //3-byte common header is this layer's own bytes (a self-contained leaf), bounded by the
                //captured frame so a truncated frame still round-trips exactly.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: POWERLINK): void {
                        const available: number = this.packet.length - this.startPos
                        this.instance.payload.setValue(available > 3 ? BufferToHex(this.readBytes(3, available - 3)) : '')
                    },
                    encode: function (this: POWERLINK): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(3, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'powerlink'

    public readonly name: string = 'Ethernet POWERLINK'

    public readonly nickname: string = 'POWERLINK'

    public readonly matchKeys: string[] = ['ethertype:88ab']

    public match(): boolean {
        //An Ethernet child selected by EtherType 0x88AB (stored as a lowercase 4-hex string). Not gated on
        //prevCodecModule.id so an EPL frame nested under a VLAN/HSR tag is still recognized. Require the
        //3-byte common header (MessageType + Destination + Source).
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.instance.etherType.getValue() !== '88ab') return false
        return this.packet.length - this.startPos >= 3
    }

    //A leaf header — the per-type body is kept verbatim as `payload`; nothing demuxes above POWERLINK.
    public readonly demuxProducers: DemuxProducer[] = []

}
