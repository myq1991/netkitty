import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * KNXnet/IP (KNX over IP, ISO/IEC 14543-3, KNX Association 03/03/02), UDP port 3671 — the IP transport
 * of the KNX building-automation bus (tunnelling KNX telegrams over IP and routing them between KNXnet/IP
 * routers). Every KNXnet/IP frame begins with a fixed 6-byte header — Header Length (always 0x06 for the
 * current spec), Protocol Version (0x10 = 1.0), a 2-byte Service Type Identifier and a 2-byte Total Length
 * (the whole frame octet count INCLUDING this 6-byte header) — followed by the service-specific body.
 *
 * Common Service Type Identifiers: 0x0201 SEARCH_REQUEST, 0x0202 SEARCH_RESPONSE, 0x0205 CONNECT_REQUEST,
 * 0x0420 TUNNELLING_REQUEST, 0x0530 ROUTING_INDICATION.
 *
 * The body layout differs per service type (HPAI discovery endpoints, connection headers, cEMI frames)
 * and several sub-structures need connection/service context, so this single-frame codec keeps the body
 * verbatim as `body` hex (byte-perfect) and does not sub-decode it. The Total Length is auto-computed from
 * the body on encode when not supplied, else honored verbatim (a crafted frame may lie); the frame is
 * bounded by Total Length (and the enclosing UDP payload) so trailing bytes are left to the codec's
 * recursion / RawData. A well-formed frame round-trips byte-for-byte.
 */
export class KNXnetIP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (KNXnetIP.#schemaCache ??= KNXnetIP.#buildSchema())
    }

    /**
     * End offset (header-relative) of this KNXnet/IP frame: the Total Length, clamped to the enclosing
     * UDP payload (udp.length − 8) when present and to the captured bytes. Bounding by the UDP payload as
     * well as Total Length keeps a lying Total Length from swallowing trailing bytes and keeps a short
     * capture in range.
     */
    static #frameEnd(self: KNXnetIP): number {
        let end: number = self.instance.totalLength.getValue(0)
        const available: number = self.packet.length - self.startPos
        const prev: any = self.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpLength: number = prev.instance.length.getValue(0)
            const udpPayload: number = udpLength - 8
            if (udpPayload >= 6 && udpPayload < end) end = udpPayload
        }
        if (end > available) end = available
        return end < 0 ? 0 : end
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'KNXnet/IP service=${serviceType} len=${totalLength}',
            properties: {
                //Header Length — the size of this header in octets, 0x06 for the current KNXnet/IP spec.
                //Kept as a plain clamped byte (honored verbatim) so a crafted frame still round-trips.
                headerLength: this.fieldUInt('headerLength', 0, 1, 'Header Length'),
                //Protocol Version — 0x10 (1.0) for the current spec. Kept verbatim.
                protocolVersion: this.fieldUInt('protocolVersion', 1, 1, 'Protocol Version'),
                //Service Type Identifier (e.g. 0x0201 SEARCH_REQUEST, 0x0420 TUNNELLING_REQUEST). Kept as a
                //plain clamped uint16 (NOT an Ajv enum) so any non-standard / crafted service type decoded
                //from the wire still re-encodes without being rejected — decode never fails, encode faithful.
                serviceType: this.fieldUInt('serviceType', 2, 2, 'Service Type'),
                totalLength: {
                    type: 'integer',
                    label: 'Total Length',
                    //minimum 0 (not 6): a crafted/corrupt frame may carry a Total Length below the 6-byte
                    //header, and that value must round-trip (honored verbatim) rather than be rejected by
                    //Ajv at the encode entry — decode never fails, encode is a faithful executor.
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: KNXnetIP): void {
                        this.instance.totalLength.setValue(BufferToUInt16(this.readBytes(4, 2)))
                    },
                    encode: function (this: KNXnetIP): void {
                        //Total Length counts the whole frame = 6-byte header + body. Honored when supplied
                        //(a crafted frame may lie); else derived from the body.
                        const provided: number | undefined = this.instance.totalLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 6 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.totalLength.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        this.instance.totalLength.setValue(value)
                        this.writeBytes(4, UInt16ToBuffer(value))
                    }
                },
                //The service-specific body after the 6-byte header, kept verbatim. Bounded by the Total
                //Length (frame ends at offset Total Length), the enclosing UDP payload and the captured
                //bytes, so trailing / pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: KNXnetIP): void {
                        const end: number = KNXnetIP.#frameEnd(this)
                        this.instance.body.setValue(end > 6 ? BufferToHex(this.readBytes(6, end - 6)) : '')
                    },
                    encode: function (this: KNXnetIP): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(6, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'knxnetip'

    public readonly name: string = 'KNXnet/IP'

    public readonly nickname: string = 'KNXnet/IP'

    public readonly matchKeys: string[] = ['udpport:3671']

    public match(): boolean {
        //KNXnet/IP rides on UDP port 3671. The header carries no strong content magic, but the first two
        //octets are effectively a fixed signature for the current spec: Header Length 0x06 and Protocol
        //Version 0x10. Require the full 6-byte header plus that signature so non-KNX 3671 traffic falls
        //through to raw. Selection stays port-bucketed (matchKeys), like the other length-bounded UDP
        //payload codecs.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.packet.length - this.startPos < 6) return false
        const header: Buffer = this.readBytes(0, 2, true)
        return header[0] === 0x06 && header[1] === 0x10
    }

    //A leaf header — the service-specific body requires per-service, connection-dependent parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
