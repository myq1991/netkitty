import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One parsed BER TLV: its tag byte, where its content starts, its length, and the offset just past it. */
type BerTLV = {tag: number, contentStart: number, contentLen: number, next: number}

/**
 * The set of Kerberos v5 application tags (RFC 4120 §5.4/5.5/5.9): AS-REQ [APPLICATION 10] = 0x6a,
 * AS-REP 0x6b, TGS-REQ 0x6c, TGS-REP 0x6d, AP-REQ 0x6e, AP-REP 0x6f, KRB-ERROR [APPLICATION 30] = 0x7e.
 * (0x6a = 0x60 | 10, 0x7e = 0x60 | 30 — application-class, constructed BER tags.)
 */
const KERBEROS_APP_TAGS: ReadonlySet<number> = new Set([0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x7e])

/**
 * Kerberos v5 (RFC 4120), UDP + TCP port 88. A Kerberos message is a single BER-encoded ASN.1
 * APPLICATION-tagged element: `<appTag> <BER length> <body>`, where the application tag names the
 * message type — 0x6a AS-REQ(10), 0x6b AS-REP(11), 0x6c TGS-REQ(12), 0x6d TGS-REP(13), 0x6e AP-REQ(14),
 * 0x6f AP-REP(15), 0x7e KRB-ERROR(30).
 *
 * Transport framing differs by L4: over UDP the message is the whole datagram (no prefix); over TCP a
 * 4-byte big-endian length prefix (the number of message bytes that follow) precedes it (RFC 4120 §7.2.2).
 * This header detects the transport via prevCodecModule.id and structures accordingly: TCP → recordLength
 * (uint32 BE) then the app-tagged message; UDP → the message directly (recordLength absent).
 *
 * Byte-perfect strategy (minimal slice): structure the application tag (msgType) + the message's BER
 * length, and keep the body verbatim as `body` hex, bounded by the decoded BER length. The BER length is
 * re-derived in minimal definite form on encode (matching what KDCs emit), and the TCP recordLength is
 * honored when supplied else derived as the encoded message length. Parsing the KDC-REQ / KDC-REP /
 * KRB-ERROR body (pvno, padata, req-body, etc.) is a later enrichment.
 */
export class Kerberos extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Kerberos.#schemaCache ??= Kerberos.#buildSchema())
    }

    // ===== Minimal BER length codec (definite length only) =====

    /** Read one TLV at `pos`; defensive against truncation (always advances, clamps to buffer). */
    static #readTLV(buf: Buffer, pos: number): BerTLV {
        if (pos >= buf.length) return {tag: 0, contentStart: pos, contentLen: 0, next: pos + 1}
        const tag: number = buf[pos]
        let p: number = pos + 1
        let len: number = p < buf.length ? buf[p] : 0
        p += 1
        if (len & 0x80) {
            const lengthBytes: number = len & 0x7f
            len = 0
            for (let i: number = 0; i < lengthBytes; i++) {
                len = len * 256 + (p < buf.length ? buf[p] : 0)
                p += 1
            }
        }
        const contentStart: number = p
        //Clamp the content to what is actually present so a lying length cannot read out of bounds.
        const contentLen: number = Math.min(len, Math.max(0, buf.length - contentStart))
        return {tag: tag, contentStart: contentStart, contentLen: contentLen, next: contentStart + contentLen}
    }

    /** Encode a definite length in minimal form (short form < 128, else long form). */
    static #encodeLength(length: number): Buffer {
        if (length < 0x80) return Buffer.from([length])
        const bytes: number[] = []
        let v: number = length
        while (v > 0) {
            bytes.unshift(v & 0xff)
            v = Math.floor(v / 256)
        }
        return Buffer.from([0x80 | bytes.length, ...bytes])
    }

    /** Offset of the app-tagged message within this header: 4 bytes past startPos for TCP, 0 for UDP. */
    #messageOffset(): number {
        return this.prevCodecModule && this.prevCodecModule.id === 'tcp' ? 4 : 0
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Kerberos msgType=${msgType}',
            properties: {
                //TCP-only 4-byte big-endian length prefix (RFC 4120 §7.2.2): the number of message bytes
                //that follow. Over UDP there is no prefix, so this field decodes/encodes nothing (the
                //transport is detected via prevCodecModule.id). Honored when supplied (a crafted frame may
                //lie); else derived at self-post-encode time as the encoded message length.
                recordLength: {
                    type: 'integer',
                    label: 'Record Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: Kerberos): void {
                        if (!(this.prevCodecModule && this.prevCodecModule.id === 'tcp')) return
                        this.instance.recordLength.setValue(BufferToUInt32(this.readBytes(0, 4)))
                    },
                    encode: function (this: Kerberos): void {
                        if (!(this.prevCodecModule && this.prevCodecModule.id === 'tcp')) return
                        const provided: number | undefined = this.instance.recordLength.getValue()
                        if (provided !== undefined && provided !== null) {
                            let value: number = provided
                            if (value > 4294967295) {
                                this.recordError(this.instance.recordLength.getPath(), 'Maximum value is 4294967295')
                                value = 4294967295
                            }
                            if (value < 0) {
                                this.recordError(this.instance.recordLength.getPath(), 'Minimum value is 0')
                                value = 0
                            }
                            this.instance.recordLength.setValue(value)
                            this.writeBytes(0, UInt32ToBuffer(value))
                        } else {
                            //Derive after the message bytes have been written: the record length counts
                            //exactly the app-tagged message (everything after this 4-byte prefix).
                            this.writeBytes(0, UInt32ToBuffer(0))
                            this.addPostSelfEncodeHandler((): void => {
                                const messageLength: number = this.headerLength - 4
                                const value: number = messageLength > 0 ? messageLength : 0
                                this.instance.recordLength.setValue(value)
                                this.writeBytes(0, UInt32ToBuffer(value))
                            }, 0)
                        }
                    }
                },
                //The message-type application tag (0x6a AS-REQ … 0x7e KRB-ERROR). It is the outer BER tag
                //of the message, so it is decoded/re-emitted together with the BER length and body below.
                msgType: {
                    type: 'integer',
                    label: 'Message Type',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: Kerberos): void {
                        const messageOffset: number = this.#messageOffset()
                        const available: number = this.packet.length - this.startPos - messageOffset
                        if (available <= 0) return
                        //Read enough to cover the tag + BER length header, then the whole message so
                        //headerLength/endPos span exactly this Kerberos message (the TCP prefix included).
                        const headerPeek: number = available < 6 ? available : 6
                        const peek: Buffer = this.readBytes(messageOffset, headerPeek, true)
                        this.instance.msgType.setValue(peek.length > 0 ? peek[0] : 0)
                        //Parse the BER length from the peek (unclamped — the peek is only the header, so
                        //#readTLV's content clamp would wrongly cap the total message length).
                        let lp: number = 1
                        let declaredLength: number = lp < peek.length ? peek[lp] : 0
                        lp += 1
                        if (declaredLength & 0x80) {
                            const lengthBytes: number = declaredLength & 0x7f
                            declaredLength = 0
                            for (let i: number = 0; i < lengthBytes; i++) {
                                declaredLength = declaredLength * 256 + (lp < peek.length ? peek[lp] : 0)
                                lp += 1
                            }
                        }
                        const total: number = Math.min(lp + declaredLength, available)
                        //Read the full message (non-dry-run) to set headerLength; then split off the body.
                        const message: Buffer = this.readBytes(messageOffset, total > 0 ? total : 0)
                        const tlv: BerTLV = Kerberos.#readTLV(message, 0)
                        this.instance.body.setValue(BufferToHex(message.subarray(tlv.contentStart, tlv.next)))
                    },
                    encode: function (this: Kerberos): void {
                        const messageOffset: number = this.#messageOffset()
                        let msgType: number = this.instance.msgType.getValue(0x6a)
                        if (msgType > 255) {
                            this.recordError(this.instance.msgType.getPath(), 'Maximum value is 255')
                            msgType = 255
                        }
                        if (msgType < 0) {
                            this.recordError(this.instance.msgType.getPath(), 'Minimum value is 0')
                            msgType = 0
                        }
                        this.instance.msgType.setValue(msgType)
                        const body: Buffer = HexToBuffer(this.instance.body.getValue(''))
                        const message: Buffer = Buffer.concat([
                            Buffer.from([msgType]),
                            Kerberos.#encodeLength(body.length),
                            body
                        ])
                        this.writeBytes(messageOffset, message)
                    }
                },
                //The message body: everything inside the application tag's BER length, kept verbatim.
                //Emitted by the msgType closure (colocated so the tag + length + body stay symmetric).
                body: {type: 'string', label: 'Body', contentEncoding: StringContentEncodingEnum.HEX}
            }
        }
    }

    public readonly id: string = 'kerberos'

    public readonly name: string = 'Kerberos'

    public readonly nickname: string = 'Kerberos'

    //KDC ports 88 on both UDP and TCP.
    public readonly matchKeys: string[] = ['tcpport:88', 'udpport:88']

    public match(): boolean {
        //Kerberos rides UDP/TCP port 88 (selected via the udpport:88 / tcpport:88 buckets). The signature
        //is port + a Kerberos application tag at the message start, so this stays a port-bucket protocol:
        //matchKeys only, NO heuristicFallback — an application-class BER tag alone is too weak to claim
        //Kerberos off port 88, and non-Kerberos traffic on 88 must fall through to raw. Over TCP the tag
        //sits after the 4-byte record-length prefix; over UDP it is the first byte.
        if (!this.prevCodecModule) return false
        const isTcp: boolean = this.prevCodecModule.id === 'tcp'
        const isUdp: boolean = this.prevCodecModule.id === 'udp'
        if (!isTcp && !isUdp) return false
        const messageOffset: number = isTcp ? 4 : 0
        if (this.packet.length - this.startPos < messageOffset + 2) return false
        const tag: number = this.readBytes(messageOffset, 1, true)[0]
        return KERBEROS_APP_TAGS.has(tag)
    }

    //A leaf header — the KDC-REQ / KDC-REP / KRB-ERROR body is kept verbatim for now.
    public readonly demuxProducers: DemuxProducer[] = []

}
