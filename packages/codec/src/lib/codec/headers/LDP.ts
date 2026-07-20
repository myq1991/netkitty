import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * LDP — Label Distribution Protocol (RFC 5036, MPLS label distribution), UDP + TCP port 646. UDP/646
 * carries the Hello discovery messages (multicast to 224.0.0.2); TCP/646 carries the session (LSP
 * establishment, label mappings). Every LDP PDU begins with a fixed 10-byte common header — a 2-byte
 * Version (== 1), a 2-byte PDU Length, a 4-byte LSR ID (the label switch router's identifier, an IPv4
 * address), and a 2-byte Label Space id — followed by one or more messages. The PDU Length counts every
 * octet after the Version and PDU Length fields (i.e. LSR ID + Label Space + the messages).
 *
 * Each message is a 1-bit U (unknown) flag + a 15-bit Message Type (0x0100 Hello, 0x0200 Initialization,
 * 0x0400 Label Mapping, …), a 2-byte Message Length, a 4-byte Message Id, and the message's parameter
 * TLVs. The per-message and per-TLV layout is type-dependent, so this codec keeps the common header
 * structured and the messages verbatim as `messages` hex (byte-perfect), bounded by the PDU Length (the
 * PDU ends at offset 4 + PDU Length) and by the transport payload (UDP length − 8), so a second pipelined
 * PDU or trailing bytes are left to the codec's recursion / RawData. The PDU Length is auto-computed from
 * the LSR ID + Label Space + messages on encode when not supplied, else honored verbatim (a crafted PDU
 * may lie). A well-formed PDU round-trips byte-for-byte; per-message / per-TLV decoding is a later
 * enrichment.
 */
export class LDP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (LDP.#schemaCache ??= LDP.#buildSchema())
    }

    /**
     * Header-relative end offset of the bytes this LDP layer may read, bounded by the transport payload so
     * a lying PDU Length never reads past the real payload into a trailing FCS. Over UDP the bound is
     * (udp.length − 8); over TCP (a session byte stream with no per-PDU record prefix) it is the captured
     * remainder. The PDU Length further bounds the consumed span inside this window (see the messages
     * field), leaving trailing / pipelined PDUs to the codec's recursion.
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
            summary: 'LDP lsr=${lsrId}:${labelSpace}',
            properties: {
                //Version of the LDP protocol; RFC 5036 defines version 1.
                version: this.fieldUInt('version', 0, 2, 'Version'),
                pduLength: {
                    type: 'integer',
                    label: 'PDU Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: LDP): void {
                        this.instance.pduLength.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: LDP): void {
                        //PDU Length counts every octet after the Version + PDU Length fields = LSR ID(4) +
                        //Label Space(2) + messages. Honored when supplied (a crafted PDU may lie); else
                        //derived from the messages hex (like BGP's Length).
                        const provided: number | undefined = this.instance.pduLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 6 + HexToBuffer(this.instance.messages.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.pduLength.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.pduLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.pduLength.setValue(value)
                        this.writeBytes(2, UInt16ToBuffer(value))
                    }
                },
                //The LSR (Label Switch Router) identifier — a 4-byte value carried as an IPv4 address.
                lsrId: this.fieldIPv4('lsrId', 4, 'LSR ID'),
                //The Label Space id: 0 means the platform-wide (per-router) label space; non-zero names a
                //per-interface label space.
                labelSpace: this.fieldUInt('labelSpace', 8, 2, 'Label Space'),
                //The messages after the 10-byte common header, kept verbatim. Bounded by the PDU Length
                //(the PDU ends at offset 4 + PDU Length) and by the transport payload, so a second pipelined
                //PDU or trailing bytes are left to the codec's recursion / RawData.
                messages: {
                    type: 'string',
                    label: 'Messages',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: LDP): void {
                        const payloadEnd: number = this.#payloadEnd()
                        const pduLength: number = this.instance.pduLength.getValue(0)
                        let end: number = 4 + pduLength
                        if (end > payloadEnd) end = payloadEnd
                        this.instance.messages.setValue(end > 10 ? BufferToHex(this.readBytes(10, end - 10)) : '')
                    },
                    encode: function (this: LDP): void {
                        const messages: string = this.instance.messages.getValue('')
                        if (messages) this.writeBytes(10, HexToBuffer(messages))
                    }
                }
            }
        }
    }

    public readonly id: string = 'ldp'

    public readonly name: string = 'Label Distribution Protocol'

    public readonly nickname: string = 'LDP'

    //LDP discovery (Hello) over UDP 646, session over TCP 646.
    public readonly matchKeys: string[] = ['tcpport:646', 'udpport:646']

    public match(): boolean {
        //LDP rides UDP/TCP port 646 (selected via the udpport:646 / tcpport:646 buckets). This stays a
        //port-bucket protocol: matchKeys only, NO heuristicFallback — a 2-byte Version of 1 alone is too
        //weak to claim LDP off port 646, and non-LDP traffic on 646 must fall through to raw. Require the
        //full 10-byte common header within the transport payload and Version == 1.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'udp' && this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadEnd() < 10) return false
        return BufferToUInt16(this.readBytes(0, 2, true)) === 1
    }

    //A leaf header — per-message / per-TLV parsing is kept verbatim for now.
    public readonly demuxProducers: DemuxProducer[] = []

}
