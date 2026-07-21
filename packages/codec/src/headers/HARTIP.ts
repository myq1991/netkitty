import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16} from '../helper/BufferToNumber'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * HART-IP (HART over IP, FieldComm Group spec HCF_SPEC-085), the process-automation transport that
 * carries HART commands over UDP and TCP port 5094. Every HART-IP message begins with a fixed 8-byte
 * header: Version (== 1), Message Type (0 Request, 1 Response, 2 Publish/Notify, 3 NAK), Message ID
 * (0 Session Initiate, 1 Session Close, 2 Keep Alive, 3 Token-Passing PDU, 4 Direct PDU), a Status
 * byte, a 2-byte Sequence Number, and a 2-byte Byte Count — the total message length including this
 * 8-byte header. The HART PDU payload follows.
 *
 * Byte-perfect strategy (minimal slice): the 8-byte header is structured; the HART PDU (a session
 * record, a command frame, or a token-passing / direct PDU whose layout depends on the Message ID and
 * the HART command set) is kept verbatim as `payload` hex, bounded by the Byte Count and the transport
 * payload (UDP length − 8, or the captured TCP bytes). The Byte Count is auto-computed from the payload
 * on encode when not supplied, else honored verbatim (a crafted message may lie); the message is bounded
 * by Byte Count so a second pipelined message or trailing bytes are left to the codec's recursion /
 * RawData. Both UDP and TCP use the same 8-byte header (HART-IP has no TCP record-marking prefix). A
 * well-formed message round-trips byte-for-byte.
 */
export class HARTIP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (HARTIP.#schemaCache ??= HARTIP.#buildSchema())
    }

    /**
     * Header-relative end offset of the transport payload available to this HART-IP message, so a lying
     * Byte Count never reads past the real transport payload and trailing / pipelined data is left to the
     * codec. Over UDP the bound is (udp.length − 8); over TCP HART-IP has no framing prefix, so the bound
     * is the captured bytes. Both clamped to what was actually captured.
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
            summary: 'HART-IP type=${messageType} id=${messageId} seq=${sequenceNumber}',
            properties: {
                //Protocol version — 1 for the current HART-IP specification. Kept verbatim so a crafted
                //message with any version still round-trips.
                version: this.fieldUInt('version', 0, 1, 'Version'),
                //0 Request, 1 Response, 2 Publish/Notify, 3 NAK. Kept as a plain clamped byte (not an Ajv
                //enum) so any non-conformant / crafted value decoded from the wire still re-encodes
                //without throwing — decode never fails and encode is a faithful executor.
                messageType: this.fieldUInt('messageType', 1, 1, 'Message Type'),
                //0 Session Initiate, 1 Session Close, 2 Keep Alive, 3 Token-Passing PDU, 4 Direct PDU.
                messageId: this.fieldUInt('messageId', 2, 1, 'Message ID'),
                //Response/communication status (0 on a request); an opaque byte kept verbatim.
                status: this.fieldUInt('status', 3, 1, 'Status'),
                //Monotonic per-session sequence number matching a response to its request.
                sequenceNumber: this.fieldUInt('sequenceNumber', 4, 2, 'Sequence Number'),
                byteCount: {
                    type: 'integer',
                    label: 'Byte Count',
                    //minimum 0 (not 8): a crafted/corrupt message may carry a Byte Count below the 8-byte
                    //header, and such a value must round-trip (honored verbatim) rather than being rejected
                    //by Ajv at the encode entry — decode never fails, encode is faithful.
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: HARTIP): void {
                        this.instance.byteCount.setValue(BufferToUInt16(this.readBytes(6, 2)))
                    },
                    encode: function (this: HARTIP): void {
                        //Byte Count is the whole message length = 8-byte header + payload. Honored when
                        //supplied (a crafted message may lie); else derived from the payload.
                        const provided: number | undefined = this.instance.byteCount.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 8 + HexToBuffer(this.instance.payload.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.byteCount.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.byteCount.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.byteCount.setValue(value)
                        this.writeBytes(6, UInt16ToBuffer(value))
                    }
                },
                //The HART PDU after the 8-byte header, kept verbatim. Bounded by the Byte Count (the
                //message ends at offset Byte Count) and the captured transport payload, so trailing /
                //pipelined data is left to the codec's recursion / RawData.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: HARTIP): void {
                        const transportEnd: number = this.#payloadEnd()
                        const byteCount: number = this.instance.byteCount.getValue(0)
                        let end: number = byteCount
                        if (end > transportEnd) end = transportEnd
                        this.instance.payload.setValue(end > 8 ? BufferToHex(this.readBytes(8, end - 8)) : '')
                    },
                    encode: function (this: HARTIP): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(8, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'hartip'

    public readonly name: string = 'HART-IP'

    public readonly nickname: string = 'HART-IP'

    //HART-IP rides UDP and TCP port 5094.
    public readonly matchKeys: string[] = ['udpport:5094', 'tcpport:5094']

    public match(): boolean {
        //HART-IP is selected via the udpport:5094 / tcpport:5094 buckets. This stays a port-bucket
        //protocol (matchKeys only, NO heuristicFallback): require the full 8-byte header within the
        //transport payload and Version == 1 so non-HART-IP traffic on 5094 falls through to raw. The
        //payload bound is the transport payload (udp.length − 8 / captured TCP bytes), not the whole
        //captured frame, so Ethernet padding is not mistaken for header bytes.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'udp' && this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadEnd() < 8) return false
        return BufferToUInt8(this.readBytes(0, 1, true)) === 1
    }

    //A leaf header — the HART PDU payload requires Message-ID- and command-set-dependent parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
