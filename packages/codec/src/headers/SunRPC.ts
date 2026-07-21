import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt32} from '../helper/BufferToNumber'
import {UInt32ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * ONC RPC / SunRPC (RFC 5531), the portmapper transport on TCP + UDP port 111. Every RPC message is a
 * 4-byte XID followed by a 4-byte Message Type (0 CALL, 1 REPLY). A CALL body continues with the RPC
 * version (== 2), the program number, the program version, the procedure, then the credential and
 * verifier auth structures (each a 4-byte flavor + 4-byte length + body) and the procedure arguments.
 * The portmapper program is 100000.
 *
 * Transport framing differs by L4 (RFC 5531 §11): over UDP the RPC message is the whole datagram; over
 * TCP a 4-byte Record Marking prefix precedes it — the high bit is the last-fragment flag and the low 31
 * bits are the fragment length. This header detects the transport via prevCodecModule.id and structures
 * accordingly: TCP → recordMark (lastFragment + fragmentLength) then the message at offset 4; UDP → the
 * message directly at offset 0.
 *
 * Byte-perfect strategy (minimal slice): structure the XID and Message Type, and for a CALL the four
 * fixed program-identity words (rpcVersion / program / programVersion / procedure); the remainder — the
 * credential, verifier and procedure arguments for a CALL, or the whole REPLY body — is kept verbatim as
 * `body` hex, bounded by the transport payload (UDP length − 8, or the TCP Record Marking fragment
 * length). The TCP fragmentLength is honored when supplied (a crafted frame may lie) else derived as the
 * encoded message length; a well-formed message round-trips byte-for-byte. Trailing / pipelined bytes are
 * left to the codec's recursion / RawData.
 */
export class SunRPC extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SunRPC.#schemaCache ??= SunRPC.#buildSchema())
    }

    /** True when this RPC message rides on TCP (a 4-byte Record Marking prefix precedes the message). */
    #isTcp(): boolean {
        return !!this.prevCodecModule && this.prevCodecModule.id === 'tcp'
    }

    /** Offset of the RPC message within this header: 4 bytes past startPos for TCP, 0 for UDP. */
    #messageOffset(): number {
        return this.#isTcp() ? 4 : 0
    }

    /**
     * Header-relative end offset of the bytes this SunRPC layer consumes, so a lying length never reads
     * past the real transport payload and trailing / pipelined data is left to the codec. Over UDP the
     * bound is (udp.length − 8); over TCP it is 4 (Record Marking) + the fragment length carried in that
     * prefix; both clamped to the captured bytes.
     */
    #payloadEnd(): number {
        let end: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpLength: number = prev.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < end) end = udpLength - 8
        } else if (prev && prev.id === 'tcp') {
            const word: number = BufferToUInt32(this.readBytes(0, 4, true))
            const fragmentLength: number = (word & 0x7fffffff) >>> 0
            const total: number = 4 + fragmentLength
            if (total < end) end = total
        }
        return end < 0 ? 0 : end
    }

    /** A 4-byte big-endian unsigned integer at the RPC-message offset + `wordOffset`, only for a CALL. */
    static #callWord(name: string, wordOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 4294967295,
            decode: function (this: SunRPC): void {
                if (this.instance.msgType.getValue(0) !== 0) return
                const offset: number = this.#messageOffset() + wordOffset
                if (this.#payloadEnd() < offset + 4) return
                (this.instance as any)[name].setValue(BufferToUInt32(this.readBytes(offset, 4)))
            },
            encode: function (this: SunRPC): void {
                if (this.instance.msgType.getValue(0) !== 0) return
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > 4294967295) {
                    this.recordError(node.getPath(), 'Maximum value is 4294967295')
                    value = 4294967295
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(this.#messageOffset() + wordOffset, UInt32ToBuffer(value))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SunRPC xid=${xid} type=${msgType}',
            properties: {
                //==== TCP-only Record Marking prefix (RFC 5531 §11) ====
                //The 4-byte word's high bit is the last-fragment flag; the low 31 bits are the fragment
                //length (message bytes that follow). Absent over UDP. The 4-byte word is written together
                //by fragmentLength (colocated) so the flag and length stay a single field on the wire.
                lastFragment: {
                    type: 'boolean',
                    label: 'Last Fragment',
                    decode: function (this: SunRPC): void {
                        if (!this.#isTcp()) return
                        this.instance.lastFragment.setValue(!!this.readBits(0, 1, 0, 1))
                    },
                    encode: function (this: SunRPC): void {
                        //Display only; the combined 4-byte word is emitted by fragmentLength below.
                        if (!this.#isTcp()) return
                        this.instance.lastFragment.setValue(!!this.instance.lastFragment.getValue(true))
                    }
                },
                fragmentLength: {
                    type: 'integer',
                    label: 'Fragment Length',
                    minimum: 0,
                    maximum: 2147483647,
                    decode: function (this: SunRPC): void {
                        if (!this.#isTcp()) return
                        const word: number = BufferToUInt32(this.readBytes(0, 4))
                        this.instance.fragmentLength.setValue((word & 0x7fffffff) >>> 0)
                    },
                    encode: function (this: SunRPC): void {
                        if (!this.#isTcp()) return
                        const last: boolean = !!this.instance.lastFragment.getValue(true)
                        const provided: number | undefined = this.instance.fragmentLength.getValue()
                        if (provided !== undefined && provided !== null) {
                            //Honored verbatim (a crafted frame may lie about the fragment length).
                            let value: number = provided
                            if (value > 2147483647) {
                                this.recordError(this.instance.fragmentLength.getPath(), 'Maximum value is 2147483647')
                                value = 2147483647
                            }
                            if (value < 0) {
                                this.recordError(this.instance.fragmentLength.getPath(), 'Minimum value is 0')
                                value = 0
                            }
                            this.instance.fragmentLength.setValue(value)
                            this.writeBytes(0, UInt32ToBuffer(((last ? 0x80000000 : 0) + value) >>> 0))
                        } else {
                            //Derive after the message bytes are written: the fragment length counts exactly
                            //the RPC message (everything after this 4-byte prefix).
                            this.writeBytes(0, UInt32ToBuffer(last ? 0x80000000 : 0))
                            this.addPostSelfEncodeHandler((): void => {
                                const messageLength: number = this.headerLength - 4
                                const value: number = messageLength > 0 ? messageLength : 0
                                this.instance.fragmentLength.setValue(value)
                                this.writeBytes(0, UInt32ToBuffer(((last ? 0x80000000 : 0) + value) >>> 0))
                            }, 0)
                        }
                    }
                },
                //==== RPC message (RFC 5531 §9) ====
                //The transaction id — an opaque 4-byte value a caller matches its REPLY to, kept as hex.
                xid: {
                    type: 'string',
                    label: 'XID',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SunRPC): void {
                        const offset: number = this.#messageOffset()
                        if (this.#payloadEnd() < offset + 4) return
                        this.instance.xid.setValue(BufferToHex(this.readBytes(offset, 4)))
                    },
                    encode: function (this: SunRPC): void {
                        this.writeBytes(this.#messageOffset(), HexToBuffer(this.instance.xid.getValue('00000000')))
                    }
                },
                //0 = CALL, 1 = REPLY. Drives whether the fixed CALL identity words are structured below.
                msgType: {
                    type: 'integer',
                    label: 'Message Type',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: SunRPC): void {
                        const offset: number = this.#messageOffset() + 4
                        if (this.#payloadEnd() < offset + 4) return
                        this.instance.msgType.setValue(BufferToUInt32(this.readBytes(offset, 4)))
                    },
                    encode: function (this: SunRPC): void {
                        const node: any = this.instance.msgType
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 4294967295) {
                            this.recordError(node.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBytes(this.#messageOffset() + 4, UInt32ToBuffer(value))
                    }
                },
                //==== CALL identity (RFC 5531 §9, decoded only for msgType == 0) ====
                rpcVersion: this.#callWord('rpcVersion', 8, 'RPC Version'),
                program: this.#callWord('program', 12, 'Program'),
                programVersion: this.#callWord('programVersion', 16, 'Program Version'),
                procedure: this.#callWord('procedure', 20, 'Procedure'),
                //The remainder kept verbatim: for a CALL the credential + verifier + procedure arguments
                //(from message offset 24); for a REPLY / other the whole body (from message offset 8).
                //Bounded by #payloadEnd so a lying length can't read past the transport payload.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SunRPC): void {
                        const isCall: boolean = this.instance.msgType.getValue(0) === 0
                        const start: number = this.#messageOffset() + (isCall ? 24 : 8)
                        const end: number = this.#payloadEnd()
                        this.instance.body.setValue(end > start ? BufferToHex(this.readBytes(start, end - start)) : '')
                    },
                    encode: function (this: SunRPC): void {
                        const isCall: boolean = this.instance.msgType.getValue(0) === 0
                        const start: number = this.#messageOffset() + (isCall ? 24 : 8)
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(start, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'sunrpc'

    public readonly name: string = 'ONC RPC'

    public readonly nickname: string = 'SunRPC'

    //Portmapper ports 111 on both TCP and UDP.
    public readonly matchKeys: string[] = ['tcpport:111', 'udpport:111']

    public match(): boolean {
        //SunRPC rides UDP/TCP port 111 (selected via the udpport:111 / tcpport:111 buckets). This stays a
        //port-bucket protocol: matchKeys only, NO heuristicFallback — the signature (XID + a Message Type
        //of 0 or 1) is too weak to claim RPC off port 111, and non-RPC traffic on 111 must fall through to
        //raw. Over TCP the message sits after the 4-byte Record Marking prefix; over UDP it is the first
        //byte. Require the fixed XID + Message Type within the transport payload and a valid Message Type.
        if (!this.prevCodecModule) return false
        const isTcp: boolean = this.prevCodecModule.id === 'tcp'
        const isUdp: boolean = this.prevCodecModule.id === 'udp'
        if (!isTcp && !isUdp) return false
        const offset: number = isTcp ? 4 : 0
        if (this.#payloadEnd() < offset + 8) return false
        const msgType: number = BufferToUInt32(this.readBytes(offset + 4, 4, true))
        return msgType === 0 || msgType === 1
    }

    //A leaf header — the credential / verifier / arguments / REPLY body are kept verbatim for now.
    public readonly demuxProducers: DemuxProducer[] = []

}
