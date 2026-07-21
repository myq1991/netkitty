import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * EAPOL — EAP over LAN (IEEE 802.1X port-based network access control), carried directly in an Ethernet
 * II frame with EtherType 0x888E (an Ethernet child — no IP/UDP). Every EAPOL frame begins with a fixed
 * 4-byte header — Protocol Version (1), Packet Type (1), and Body Length (2, big-endian, the count of
 * body bytes that follow the header) — then `Body Length` bytes of type-specific body.
 *
 * The Packet Type selects the body: 0 = EAP-Packet (an encapsulated EAP message), 1 = EAPOL-Start,
 * 2 = EAPOL-Logoff, 3 = EAPOL-Key (e.g. the WPA/RSN 4-way-handshake key descriptor), 4 = EAPOL-Encapsulated-
 * ASF-Alert. Start/Logoff carry an empty body (Body Length 0). The body is kept verbatim as `body` hex so
 * every frame — including the EAP message and the 802.11 key descriptor, both of which are separate
 * cross-frame/stateful parsers — round-trips byte-for-byte; per-type semantic decoding is a later
 * enrichment.
 *
 * The body is bounded by Body Length (body ends at offset 4 + bodyLength) and the captured bytes, so any
 * trailing bytes — Ethernet padding to the 60-byte minimum, or a pipelined frame — are left to the
 * codec's recursion / RawData rather than swallowed. Body Length is honored verbatim on encode when
 * supplied (a crafted frame may lie), else derived from the body byte count. A well-formed frame
 * round-trips byte-for-byte.
 */
export class EAPOL extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (EAPOL.#schemaCache ??= EAPOL.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'EAPOL type=${packetType} len=${bodyLength}',
            properties: {
                //Protocol Version — 1 (802.1X-2001), 2 (802.1X-2004), 3 (802.1X-2010).
                version: this.fieldUInt('version', 0, 1, 'Version'),
                //Packet Type selects the body kind. Constrained to the defined types for the editor; an
                //unknown type still decodes best-effort (decode never validates) but is out of enum on encode.
                packetType: {
                    type: 'integer',
                    label: 'Packet Type',
                    minimum: 0,
                    maximum: 255,
                    enum: [0, 1, 2, 3, 4],
                    decode: function (this: EAPOL): void {
                        this.instance.packetType.setValue(this.readBytes(1, 1)[0])
                    },
                    encode: function (this: EAPOL): void {
                        let value: number = this.instance.packetType.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 255) {
                            this.recordError(this.instance.packetType.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) {
                            this.recordError(this.instance.packetType.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.packetType.setValue(value)
                        this.writeBytes(1, Buffer.from([value & 0xff]))
                    }
                },
                bodyLength: {
                    type: 'integer',
                    label: 'Body Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: EAPOL): void {
                        const b: Buffer = this.readBytes(2, 2)
                        this.instance.bodyLength.setValue((b[0] << 8) | b[1])
                    },
                    encode: function (this: EAPOL): void {
                        //Body Length counts only the body that follows the 4-byte header. Honored when
                        //supplied (a crafted frame may lie); else derived from the body byte count.
                        const provided: number | undefined = this.instance.bodyLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.bodyLength.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.bodyLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.bodyLength.setValue(value)
                        this.writeBytes(2, Buffer.from([(value >> 8) & 0xff, value & 0xff]))
                    }
                },
                //The type-specific body (EAP message / EAPOL-Key descriptor / …), kept verbatim. Bounded
                //by Body Length (body ends at offset 4 + bodyLength) and the captured bytes, so trailing
                //padding / a pipelined frame is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: EAPOL): void {
                        const remaining: number = this.packet.length - this.startPos
                        const bodyLength: number = this.instance.bodyLength.getValue(0)
                        let end: number = 4 + bodyLength
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 4 ? BufferToHex(this.readBytes(4, end - 4)) : '')
                    },
                    encode: function (this: EAPOL): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(4, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'eapol'

    public readonly name: string = 'EAP over LAN'

    public readonly nickname: string = 'EAPOL'

    public readonly matchKeys: string[] = ['ethertype:888e']

    public match(): boolean {
        //An Ethernet child selected by EtherType 0x888E (stored as a lowercase 4-hex string). Require the
        //full 4-byte fixed header to be present.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'eth') return false
        if (this.prevCodecModule.instance.etherType.getValue() !== '888e') return false
        return this.packet.length - this.startPos >= 4
    }

    //A leaf header — the EAP message / EAPOL-Key descriptor requires separate, stateful parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
