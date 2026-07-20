import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * OpenVPN, the control/data channel protocol on UDP + TCP port 1194. Every packet begins with a single
 * opcode/key-id octet: the high 5 bits are the opcode (1 P_CONTROL_HARD_RESET_CLIENT_V1, 2 …SERVER_V1,
 * 3 P_CONTROL_SOFT_RESET_V1, 4 P_ACK_V1, 5 P_CONTROL_V1, 6 P_DATA_V1, 7 …HARD_RESET_CLIENT_V2,
 * 8 …HARD_RESET_SERVER_V2, 9 P_DATA_V2) and the low 3 bits are the key id. For a control packet the
 * octet is followed by an 8-byte session id, an optional (config-dependent) HMAC + packet-id when
 * tls-auth/tls-crypt is used, a message-packet-id array (ACKs) and the message packet-id; a data packet
 * carries the encrypted/authenticated payload. None of that tail is self-describing without the session's
 * negotiated crypto parameters.
 *
 * Transport framing differs by L4: over UDP the OpenVPN packet is the whole datagram; over TCP a 2-byte
 * big-endian length prefix precedes each packet (OpenVPN's own record framing on a stream). This header
 * detects the transport via prevCodecModule.id and structures accordingly — TCP → length prefix then the
 * packet at offset 2; UDP → the packet directly at offset 0.
 *
 * Byte-perfect strategy (minimal slice): structure the opcode + key-id bit split, and keep the remainder
 * (session id / HMAC / packet-id / ack array for a control packet, or the payload for a data packet)
 * verbatim as `body` hex, bounded by the transport payload (UDP length − 8, or 2 + the TCP length prefix).
 * The TCP length prefix is honored when supplied (a crafted frame may lie) else derived from the encoded
 * packet bytes; a well-formed packet round-trips byte-for-byte. Trailing / pipelined bytes are left to the
 * codec's recursion / RawData.
 */
export class OpenVPN extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (OpenVPN.#schemaCache ??= OpenVPN.#buildSchema())
    }

    /** True when this OpenVPN packet rides on TCP (a 2-byte big-endian length prefix precedes the packet). */
    #isTcp(): boolean {
        return !!this.prevCodecModule && this.prevCodecModule.id === 'tcp'
    }

    /** Offset of the OpenVPN packet within this header: 2 bytes past startPos for TCP, 0 for UDP. */
    #packetOffset(): number {
        return this.#isTcp() ? 2 : 0
    }

    /**
     * Header-relative end offset of the bytes this OpenVPN layer consumes, so a lying length never reads
     * past the real transport payload and trailing / pipelined data is left to the codec. Over UDP the
     * bound is (udp.length − 8); over TCP it is 2 (length prefix) + the length carried in that prefix;
     * both clamped to the captured bytes.
     */
    #payloadEnd(): number {
        let end: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpLength: number = prev.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < end) end = udpLength - 8
        } else if (prev && prev.id === 'tcp') {
            if (end >= 2) {
                const prefix: number = BufferToUInt16(this.readBytes(0, 2, true))
                const total: number = 2 + prefix
                if (total < end) end = total
            }
        }
        return end < 0 ? 0 : end
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'OpenVPN opcode=${opcode} keyId=${keyId}',
            properties: {
                //==== TCP-only 2-byte big-endian record length prefix ====
                //The number of OpenVPN packet bytes that follow this prefix. Absent over UDP.
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: OpenVPN): void {
                        if (!this.#isTcp()) return
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(0, 2)))
                    },
                    encode: function (this: OpenVPN): void {
                        if (!this.#isTcp()) return
                        const provided: number | undefined = this.instance.length.getValue()
                        if (provided !== undefined && provided !== null) {
                            //Honored verbatim (a crafted frame may lie about the record length).
                            let value: number = provided
                            if (value > 65535) {
                                this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                                value = 65535
                            }
                            if (value < 0) {
                                this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                                value = 0
                            }
                            this.instance.length.setValue(value)
                            this.writeBytes(0, UInt16ToBuffer(value))
                        } else {
                            //Derive after the packet bytes are written: the prefix counts exactly the
                            //OpenVPN packet (everything after this 2-byte prefix).
                            this.writeBytes(0, UInt16ToBuffer(0))
                            this.addPostSelfEncodeHandler((): void => {
                                const packetLength: number = this.headerLength - 2
                                const value: number = packetLength > 0 ? (packetLength > 65535 ? 65535 : packetLength) : 0
                                this.instance.length.setValue(value)
                                this.writeBytes(0, UInt16ToBuffer(value))
                            }, 0)
                        }
                    }
                },
                //==== opcode/key-id octet ====
                //High 5 bits: the packet opcode (message type). Any value 0-31 is emitted faithfully.
                opcode: {
                    type: 'integer',
                    label: 'Opcode',
                    minimum: 0,
                    maximum: 31,
                    decode: function (this: OpenVPN): void {
                        this.instance.opcode.setValue(this.readBits(this.#packetOffset(), 1, 0, 5))
                    },
                    encode: function (this: OpenVPN): void {
                        const node: any = this.instance.opcode
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 31) {
                            this.recordError(node.getPath(), 'Maximum value is 31')
                            value = 31
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBits(this.#packetOffset(), 1, 0, 5, value)
                    }
                },
                //Low 3 bits: the key id selecting the negotiated crypto key set (0-7).
                keyId: {
                    type: 'integer',
                    label: 'Key ID',
                    minimum: 0,
                    maximum: 7,
                    decode: function (this: OpenVPN): void {
                        this.instance.keyId.setValue(this.readBits(this.#packetOffset(), 1, 5, 3))
                    },
                    encode: function (this: OpenVPN): void {
                        const node: any = this.instance.keyId
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 7) {
                            this.recordError(node.getPath(), 'Maximum value is 7')
                            value = 7
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBits(this.#packetOffset(), 1, 5, 3, value)
                    }
                },
                //The remainder kept verbatim: for a control packet the session id + optional HMAC/packet-id
                //+ ack array + message packet-id; for a data packet the encrypted payload. Bounded by
                //#payloadEnd so a lying length can't read past the transport payload.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: OpenVPN): void {
                        const start: number = this.#packetOffset() + 1
                        const end: number = this.#payloadEnd()
                        this.instance.body.setValue(end > start ? BufferToHex(this.readBytes(start, end - start)) : '')
                    },
                    encode: function (this: OpenVPN): void {
                        const start: number = this.#packetOffset() + 1
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(start, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'openvpn'

    public readonly name: string = 'OpenVPN Protocol'

    public readonly nickname: string = 'OpenVPN'

    //OpenVPN's default port 1194 on both UDP and TCP.
    public readonly matchKeys: string[] = ['udpport:1194', 'tcpport:1194']

    public match(): boolean {
        //OpenVPN rides UDP/TCP port 1194 (selected via the udpport:1194 / tcpport:1194 buckets). This
        //stays a port-bucket protocol: matchKeys only, NO heuristicFallback — the opcode/key-id octet is
        //too weak a signature to claim OpenVPN off port 1194. Over TCP the packet sits after the 2-byte
        //length prefix; over UDP it is the first byte. Require at least the opcode octet within the
        //transport payload.
        if (!this.prevCodecModule) return false
        const isTcp: boolean = this.prevCodecModule.id === 'tcp'
        const isUdp: boolean = this.prevCodecModule.id === 'udp'
        if (!isTcp && !isUdp) return false
        const offset: number = isTcp ? 2 : 0
        return this.#payloadEnd() >= offset + 1
    }

    //A leaf header — the control/data tail requires the session's negotiated crypto parameters to parse.
    public readonly demuxProducers: DemuxProducer[] = []

}
