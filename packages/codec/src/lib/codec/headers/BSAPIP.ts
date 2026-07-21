import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * BSAP-IP — Bristol/Emerson (Bristol Babcock) BSAP over UDP, well-known UDP port 1234. BSAP (Bristol
 * Standard Asynchronous/Synchronous Protocol) is a proprietary master/slave SCADA protocol for Network
 * 3000 (DPC 33xx) and ControlWave devices; ControlWave Ethernet nodes encapsulate it in UDP and default
 * to port 1234 (documented by the Emerson/Kepware/PTC-TOPServer/AUTOSOL driver manuals).
 *
 * ⚠️ There is NO public authoritative on-wire byte layout for the BSAP-IP encapsulation. The serial BSAP
 * link protocol (DLE/STX framing, 16-bit CRC-CCITT) is documented in Emerson's "BSAP Communications
 * Application Programmer's Reference", but the IP framing (message flags / local-address / NPDU sequence
 * & function fields) is not publicly specified, and Wireshark's built-in `bsap` dissector is an unrelated
 * name collision (BSSAP, the GSM/ANSI A-interface over SCCP — fields `bsap.dlci.sapi`, `bsap.pdu_type`
 * routing to `ansi_a_bsmap`/`ansi_a_dtap`), NOT this Bristol SCADA protocol.
 *
 * Because no field offsets can be pinned down with confidence, this is a deliberately conservative
 * minimal slice: it claims BSAP-IP by its well-known UDP port (like ENIP claims 44818 with no content
 * magic) and carries the entire UDP payload verbatim as `payload` hex (byte-perfect). The payload is
 * bounded by the UDP datagram (the codec has already advanced past the UDP header), so nothing beyond
 * the datagram is absorbed. A frame round-trips byte-for-byte, and decode never throws. Sub-decoding the
 * BSAP message (sequence / function / routing fields) is left for when an authoritative spec is available.
 */
export class BSAPIP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (BSAPIP.#schemaCache ??= BSAPIP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'BSAP-IP over UDP/1234',
            properties: {
                //The whole UDP payload, kept verbatim. No public on-wire layout exists to sub-decode it,
                //so it is carried as opaque hex. Bounded by the captured bytes (= the UDP datagram, since
                //the codec advanced startPos past the UDP header), so trailing frames are not absorbed.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: BSAPIP): void {
                        const remaining: number = this.packet.length - this.startPos
                        this.instance.payload.setValue(remaining > 0 ? BufferToHex(this.readBytes(0, remaining)) : '')
                    },
                    encode: function (this: BSAPIP): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(0, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'bsap'

    public readonly name: string = 'Bristol/Emerson BSAP over IP'

    public readonly nickname: string = 'BSAP-IP'

    //Well-known UDP port 1234 (ControlWave / Network 3000 default). No content magic exists for BSAP-IP,
    //so selection is port-bucketed only (no heuristicFallback) — the same conservative stance as ENIP.
    public readonly matchKeys: string[] = ['udpport:1234']

    public match(): boolean {
        //BSAP-IP rides on UDP port 1234. There is no content signature to validate, so the well-known
        //port is the signature; require at least one payload byte so an empty datagram falls through to
        //raw rather than being claimed as an empty BSAP-IP layer.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        return this.packet.length - this.startPos >= 1
    }

    //A leaf header — the BSAP message body has no public on-wire spec to demux further.
    public readonly demuxProducers: DemuxProducer[] = []

}
