import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * One RTPS submessage kept structurally but with its body verbatim. `submessageId` + `flags` +
 * `submessageLength` (all honored on the wire) and the hex `body`. The submessage-header endianness is
 * the low bit of `flags` (the EndiannessFlag, E): it decides the byte order of `submessageLength` — the
 * body itself is byte-opaque so its internal endianness never matters here.
 */
type RtpsSubmessage = {
    submessageId: number
    flags: number
    submessageLength: number
    body: string
}

/**
 * RTPS — the OMG DDSI-RTPS wire protocol (Real-Time Publish-Subscribe) that carries DDS traffic for
 * industrial IoT / robotics. It rides UDP on dynamically negotiated ports (the well-known 7400-range
 * discovery ports are only defaults), so selection is by content signature, not port: every RTPS
 * message opens with a 20-byte header — the 4-byte magic 'RTPS' (0x52545053), a 2-byte protocol
 * version, a 2-byte vendorId, and a 12-byte guidPrefix — followed by a sequence of submessages.
 *
 * Each submessage is a 4-byte submessage header — submessageId(1), flags(1), submessageLength(2) —
 * then `submessageLength` body octets. The single most important quirk: the low bit of the flags octet
 * is the EndiannessFlag, and it governs the byte order of THAT submessage's submessageLength field
 * (little-endian when set, big-endian when clear). A submessageLength of 0 is legal for the final
 * submessage and means "the rest of the message"; it is honored verbatim so the frame round-trips.
 *
 * The submessage bodies (DATA's serialized payload, ACKNACK bitmaps, INFO_TS timestamps, …) are cross-
 * message, QoS- and type-dependent state, so they are kept verbatim as hex (byte-perfect) rather than
 * sub-decoded. The whole message is bounded by the UDP payload (the parent UDP Length when present),
 * and every submessageLength is honored on encode (a crafted message may lie), else derived from the
 * body. A well-formed message round-trips byte-for-byte.
 */
export class RTPS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (RTPS.#schemaCache ??= RTPS.#buildSchema())
    }

    /** The EndiannessFlag is the low bit of the flags octet: set → little-endian submessage header. */
    static #isLittleEndian(flags: number): boolean {
        return (flags & 0x01) === 0x01
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'RTPS v${protocolVersion} vendor=${vendorId}',
            properties: {
                //The 4-byte magic 'RTPS' (0x52545053). Kept verbatim so any variant round-trips; it is
                //also the content signature match() gates on.
                magic: this.fieldHex('magic', 0, 4, 'Magic'),
                //Protocol version (major.minor), e.g. 0x0201 = RTPS 2.1. Two opaque octets.
                protocolVersion: this.fieldHex('protocolVersion', 4, 2, 'Protocol Version'),
                //Vendor ID (OMG-assigned), e.g. 0x0101 = RTI Connext. Two opaque octets.
                vendorId: this.fieldHex('vendorId', 6, 2, 'Vendor ID'),
                //The 12-byte GUID prefix identifying the participant that sent this message.
                guidPrefix: this.fieldHex('guidPrefix', 8, 12, 'GUID Prefix'),
                //The submessage sequence after the 20-byte header. Each is a 4-byte submessage header
                //(id/flags/length) plus a verbatim body. Bounded by BOTH the declared submessageLength
                //AND the bytes actually present (the UDP payload), so a lying length cannot spawn phantom
                //submessages past the end of the buffer, and the loop always advances by at least 4.
                submessages: {
                    type: 'array',
                    label: 'Submessages',
                    items: {
                        type: 'object',
                        label: 'Submessage',
                        properties: {
                            submessageId: {
                                type: 'integer',
                                label: 'Submessage ID',
                                minimum: 0,
                                maximum: 255
                            },
                            flags: {
                                type: 'integer',
                                label: 'Flags',
                                minimum: 0,
                                maximum: 255
                            },
                            submessageLength: {
                                type: 'integer',
                                label: 'Submessage Length',
                                minimum: 0,
                                maximum: 65535
                            },
                            body: {
                                type: 'string',
                                label: 'Body',
                                contentEncoding: StringContentEncodingEnum.HEX
                            }
                        }
                    },
                    decode: function (this: RTPS): void {
                        //Cap the submessage walk at the UDP payload end so trailing frame padding / a
                        //pipelined datagram is never absorbed. The parent UDP Length spans the 8-byte UDP
                        //header + payload, so the RTPS payload is (Length − 8) bytes; else fall back to the
                        //captured bytes.
                        let cap: number = this.packet.length - this.startPos
                        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
                            const payload: number = this.prevCodecModule.instance.length.getValue(0) - 8
                            if (payload >= 0 && payload < cap) cap = payload
                        }
                        const submessages: RtpsSubmessage[] = []
                        let offset: number = 20
                        while (offset + 4 <= cap) {
                            const submessageId: number = this.readBytes(offset, 1)[0]
                            const flags: number = this.readBytes(offset + 1, 1)[0]
                            const lengthBytes: Buffer = this.readBytes(offset + 2, 2)
                            const submessageLength: number = RTPS.#isLittleEndian(flags)
                                ? (lengthBytes[0] | (lengthBytes[1] << 8))
                                : ((lengthBytes[0] << 8) | lengthBytes[1])
                            offset += 4
                            //A submessageLength of 0 means "the rest of the message" (only legal on the
                            //last submessage). Otherwise the body is `submessageLength` bytes, clamped to
                            //the bytes actually present so a lying length cannot read past the buffer.
                            let bodyLength: number = submessageLength === 0 ? cap - offset : submessageLength
                            if (bodyLength > cap - offset) bodyLength = cap - offset
                            if (bodyLength < 0) bodyLength = 0
                            const body: Buffer = bodyLength ? this.readBytes(offset, bodyLength) : Buffer.alloc(0)
                            offset += bodyLength
                            submessages.push({
                                submessageId: submessageId,
                                flags: flags,
                                submessageLength: submessageLength,
                                body: BufferToHex(body)
                            })
                        }
                        this.instance.submessages.setValue(submessages)
                    },
                    encode: function (this: RTPS): void {
                        const submessages: RtpsSubmessage[] | undefined = this.instance.submessages.getValue()
                        if (!submessages) return
                        let offset: number = 20
                        submessages.forEach((submessage: RtpsSubmessage): void => {
                            const submessageId: number = submessage.submessageId ? submessage.submessageId : 0
                            const flags: number = submessage.flags ? submessage.flags : 0
                            const body: Buffer = HexToBuffer(submessage.body ? submessage.body : '')
                            //Honor an explicitly supplied submessageLength verbatim (a number, including a
                            //legal 0 = "rest of message"); derive from the body length only when absent.
                            const provided: number | undefined = submessage.submessageLength
                            let submessageLength: number = (provided !== undefined && provided !== null) ? provided : body.length
                            if (submessageLength > 65535) submessageLength = 65535
                            if (submessageLength < 0) submessageLength = 0
                            this.writeBytes(offset, Buffer.from([submessageId & 0xff, flags & 0xff]))
                            //submessageLength byte order follows this submessage's EndiannessFlag (flags bit 0).
                            const lengthBytes: Buffer = RTPS.#isLittleEndian(flags)
                                ? Buffer.from([submessageLength & 0xff, (submessageLength >> 8) & 0xff])
                                : Buffer.from([(submessageLength >> 8) & 0xff, submessageLength & 0xff])
                            this.writeBytes(offset + 2, lengthBytes)
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

    public readonly id: string = 'rtps'

    public readonly name: string = 'Real-Time Publish-Subscribe Wire Protocol'

    public readonly nickname: string = 'RTPS'

    //No demux keys: RTPS uses dynamically negotiated UDP ports, so it is a content-heuristic child
    //recognized by its 'RTPS' magic rather than a well-known port.
    public readonly matchKeys: string[] = []

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        //RTPS rides UDP on dynamic ports; require the parent to be UDP, the full 20-byte header to be
        //present, and the 4-byte magic 'RTPS' (0x52545053) — a strong, distinctive content signature.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.packet.length - this.startPos < 20) return false
        return BufferToHex(this.readBytes(0, 4, true)) === '52545053'
    }

    //A leaf header — submessage bodies are QoS/type-dependent and kept verbatim, decoded later.
    public readonly demuxProducers: DemuxProducer[] = []

}
