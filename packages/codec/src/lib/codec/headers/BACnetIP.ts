import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * BACnet/IP — the BACnet Virtual Link Control (BVLC) layer that carries BACnet over UDP (ANSI/ASHRAE
 * 135 Annex J), UDP port 47808 (0xBAC0). Every message starts with a 4-byte BVLC header: a Type octet
 * (0x81 for BACnet/IP), a Function octet (e.g. Original-Unicast-NPDU 0x0A, Original-Broadcast-NPDU 0x0B,
 * Forwarded-NPDU 0x04, BVLC-Result 0x00), and a 2-byte Length that counts the WHOLE BVLC message
 * (header + everything after). The bytes after the header are the NPDU and APDU (and, for a few
 * functions, a BVLC-specific address prefix).
 *
 * This codec decodes the BVLC header structurally and keeps the NPDU + APDU verbatim as `payload` hex,
 * bounded by the BVLC Length (so a trailing/coalesced datagram is left to RawData). The NPDU's
 * conditional routing fields are intricate enough that structuring them belongs to a later slice. The
 * Length is honored when supplied, else derived from the payload; a well-formed message round-trips
 * byte-for-byte.
 */
export class BACnetIP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (BACnetIP.#schemaCache ??= BACnetIP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'BACnet/IP func=${function}',
            properties: {
                type: this.fieldHex('type', 0, 1, 'Type'),
                'function': this.fieldUInt('function', 1, 1, 'Function'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: BACnetIP): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: BACnetIP): void {
                        //BVLC Length counts the whole message (4-byte header + payload). Honored when
                        //supplied (a crafted message may lie); else derived from the payload.
                        const provided: number | undefined = this.instance.length.getValue()
                        const value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 4 + HexToBuffer(this.instance.payload.getValue('')).length
                        this.instance.length.setValue(value)
                        this.writeBytes(2, UInt16ToBuffer(value))
                    }
                },
                //NPDU + APDU (and any BVLC address prefix), kept verbatim and bounded by the BVLC Length
                //so a trailing/coalesced datagram is left to raw.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: BACnetIP): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        let end: number = length >= 4 ? length : remaining
                        if (end > remaining) end = remaining
                        this.instance.payload.setValue(end > 4 ? BufferToHex(this.readBytes(4, end - 4)) : '')
                    },
                    encode: function (this: BACnetIP): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(4, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'bacnet'

    public readonly name: string = 'BACnet/IP'

    public readonly nickname: string = 'BACnet'

    public readonly matchKeys: string[] = ['udpport:47808']

    public match(): boolean {
        //BACnet/IP rides on UDP port 47808. Require the 4-byte BVLC header and the 0x81 type signature so
        //non-BACnet traffic on that port falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.packet.length - this.startPos < 4) return false
        return this.readBytes(0, 1, true)[0] === 0x81
    }

    //A leaf header — the NPDU/APDU are kept verbatim (structuring them is a later slice).
    public readonly demuxProducers: DemuxProducer[] = []

}
