import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt32} from '../helper/BufferToNumber'
import {UInt32ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * FOUNDATION Fieldbus HSE — High Speed Ethernet (IEC 61158), the process-control fieldbus mapping onto
 * TCP + UDP ports 1089/1090/1091. Every HSE frame carries an FDA (Field Device Access) message, which
 * begins with a 12-octet FDA Message Header (FF-588 §6.3 / Wireshark `ff` dissector layout):
 *
 *   0    Version                          (1 octet)  FDA message version
 *   1    Options                          (1 octet)  trailer-presence bitmap + pad length; bit fields are
 *                                                    0x80 msg-num, 0x40 invoke-id, 0x20 timestamp,
 *                                                    0x10 reserved, 0x08 ext-ctrl, 0x07 pad length —
 *                                                    kept as the whole octet so every bit round-trips
 *   2    Protocol Id And Confirmed Type   (1 octet)  0xFC protocol id (FDA/SM/FMS/LAN), 0x03 confirmed msg type
 *   3    Service                          (1 octet)  0x80 confirmed flag, 0x7F service id
 *   4..7 FDA Address                       (4 octets) session/address handle, kept as hex (BASE_HEX)
 *   8..11 Message Length                   (4 octets) total octet count of the whole FDA message (this
 *                                                    12-octet header + service body + trailer)
 *
 * The service-specific body (and any optional trailer selected by the Options bits) follows the header.
 * Its layout is per protocol id + service id and needs cross-message session context, so this
 * single-message codec keeps everything after the header verbatim as `body` hex (byte-perfect) and does
 * not sub-decode it (a later enrichment). Message Length delimits this layer: the FDA message ends at
 * `Message Length` octets, so a second pipelined FDA message or trailing/padding bytes are left to the
 * codec's recursion / RawData rather than swallowed. Message Length is honored when supplied (a crafted
 * frame may lie) else derived from the header + body on encode. A well-formed message round-trips
 * byte-for-byte.
 *
 * Transport framing is identical over TCP and UDP — the FDA message has no record/length prefix of its
 * own (unlike Kerberos/SunRPC over TCP); Message Length is the sole delimiter. The only transport-aware
 * detail is the payload bound: over UDP the message is capped by (udp.length − 8) so Ethernet padding is
 * never read into `body`; over TCP it is capped by the captured stream bytes.
 */
export class FoundationFieldbusHSE extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (FoundationFieldbusHSE.#schemaCache ??= FoundationFieldbusHSE.#buildSchema())
    }

    /** Length of the fixed FDA Message Header in octets. */
    static readonly #HEADER_LENGTH: number = 12

    /**
     * Header-relative end offset of the bytes this layer may read: the captured remainder, further capped
     * by (udp.length − 8) over UDP so a lying Message Length can never read past the real transport
     * payload (and Ethernet padding is never swallowed into `body`). Over TCP the stream bytes are the cap.
     */
    #payloadEnd(): number {
        let end: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpLength: number = prev.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < end) end = udpLength - 8
        }
        return end < 0 ? 0 : end
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'FF-HSE ver=${version} svc=${service} len=${messageLength}',
            properties: {
                //FDA Message Version (FF-588 §6.3).
                version: this.fieldUInt('version', 0, 1, 'Version'),
                //Options: a trailer-presence bitmap (0x80 message number, 0x40 invoke id, 0x20 timestamp,
                //0x08 extended control) plus 0x10 reserved and a 0x07 pad-length. Kept as the whole octet
                //so every reserved/flag bit round-trips untouched.
                options: this.fieldUInt('options', 1, 1, 'Options'),
                //Protocol Id And Confirmed Msg Type: 0xFC = protocol id (FDA/SM/FMS/LAN dispatch),
                //0x03 = confirmed message type. Whole octet kept so both sub-fields round-trip.
                protocolAndType: this.fieldUInt('protocolAndType', 2, 1, 'Protocol Id And Confirmed Msg Type'),
                //Service: 0x80 = confirmed flag, 0x7F = service id. Whole octet kept.
                service: this.fieldUInt('service', 3, 1, 'Service'),
                //FDA Address — a session/address handle, kept verbatim as hex (BASE_HEX in the dissector).
                fdaAddress: this.fieldHex('fdaAddress', 4, 4, 'FDA Address'),
                messageLength: {
                    type: 'integer',
                    label: 'Message Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: FoundationFieldbusHSE): void {
                        this.instance.messageLength.setValue(BufferToUInt32(this.readBytes(8, 4)))
                    },
                    encode: function (this: FoundationFieldbusHSE): void {
                        //Total octet count of the whole FDA message = 12-byte header + body. Honored when
                        //supplied (a crafted frame may lie); else derived from the body.
                        const provided: number | undefined = this.instance.messageLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : FoundationFieldbusHSE.#HEADER_LENGTH + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.messageLength.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.messageLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.messageLength.setValue(value)
                        this.writeBytes(8, UInt32ToBuffer(value))
                    }
                },
                //The service body + optional trailer after the 12-byte header, kept verbatim. Bounded by
                //Message Length (the FDA message ends at that octet count) and by the transport payload, so
                //trailing / pipelined FDA messages and Ethernet padding are left to the codec's recursion.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: FoundationFieldbusHSE): void {
                        const payloadEnd: number = this.#payloadEnd()
                        const messageLength: number = this.instance.messageLength.getValue(0)
                        let end: number = messageLength
                        if (end > payloadEnd) end = payloadEnd
                        this.instance.body.setValue(
                            end > FoundationFieldbusHSE.#HEADER_LENGTH
                                ? BufferToHex(this.readBytes(FoundationFieldbusHSE.#HEADER_LENGTH, end - FoundationFieldbusHSE.#HEADER_LENGTH))
                                : ''
                        )
                    },
                    encode: function (this: FoundationFieldbusHSE): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(FoundationFieldbusHSE.#HEADER_LENGTH, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'ffhse'

    public readonly name: string = 'FOUNDATION Fieldbus HSE'

    public readonly nickname: string = 'FF-HSE'

    //HSE FDA agent ports 1089/1090/1091 on both TCP and UDP.
    public readonly matchKeys: string[] = [
        'tcpport:1089', 'udpport:1089',
        'tcpport:1090', 'udpport:1090',
        'tcpport:1091', 'udpport:1091'
    ]

    public match(): boolean {
        //FF-HSE rides TCP/UDP ports 1089-1091 (selected via the port buckets). This stays a port-bucket
        //protocol: matchKeys only, NO heuristicFallback — the FDA header has no distinctive magic to
        //claim FF off its well-known ports, and Wireshark itself dissects these ports by port alone. The
        //only guard is that the full 12-byte FDA Message Header fits within the transport payload (payload
        //length, not whole-frame remainder, so Ethernet padding on a short UDP datagram does not match).
        if (!this.prevCodecModule) return false
        const prev: any = this.prevCodecModule
        if (prev.id !== 'tcp' && prev.id !== 'udp') return false
        if (this.#payloadEnd() < FoundationFieldbusHSE.#HEADER_LENGTH) return false
        return true
    }

    //A leaf header — the service body / trailer needs per-protocol, session-dependent parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
