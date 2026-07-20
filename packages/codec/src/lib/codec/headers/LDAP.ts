import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One parsed BER TLV within a buffer: its tag byte, where its content starts, its length, and the offset just past it. */
type BerTLV = {tag: number, contentStart: number, contentLen: number, next: number}

/**
 * LDAP — Lightweight Directory Access Protocol (RFC 4511), over TCP port 389. Each LDAPMessage is a
 * BER-encoded ASN.1 SEQUENCE: SEQUENCE { messageID INTEGER, protocolOp CHOICE [, controls] }, where
 * protocolOp is a context/application-tagged element identifying the operation — 0x60 bindRequest,
 * 0x61 bindResponse, 0x63 searchRequest, 0x64 searchResultEntry, 0x65 searchResultDone,
 * 0x42 unbindRequest, and so on.
 *
 * Minimal slice (byte-perfect): the outer SEQUENCE and its length are decoded, the messageID INTEGER is
 * decoded as a signed integer, and the protocolOp is split into its TAG (one byte, e.g. 0x60) plus its
 * BODY — the protocolOp length/content and any trailing controls — kept verbatim as `protocolOpData`
 * hex. Re-encode rebuilds the SEQUENCE with minimal-definite lengths, re-emits the messageID with
 * minimal two's-complement BER, and appends the protocolOp tag + verbatim body. So any operation
 * round-trips exactly without a per-op encoder. Full BER structuring of each operation (bind DN/auth,
 * search filter/attributes, result codes …) is a later, separate slice.
 *
 * Non-minimal BER lengths (long-form where short-form would do) regularize to minimal form on re-encode,
 * exactly like SNMP — standard LDAP servers emit minimal lengths, so real traffic is byte-perfect.
 */
export class LDAP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (LDAP.#schemaCache ??= LDAP.#buildSchema())
    }

    // ===== Minimal BER/DER codec (definite length only) — mirrors SNMP.ts =====

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

    /** Decode a BER INTEGER content (big-endian two's-complement, signed). */
    static #berInt(buf: Buffer): number {
        if (buf.length === 0) return 0
        let value: number = 0
        for (const byte of buf) value = value * 256 + byte
        if (buf[0] & 0x80) value -= Math.pow(2, 8 * buf.length)
        return value
    }

    /** Encode a signed integer as minimal BER INTEGER content bytes. */
    static #intToBer(value: number): Buffer {
        const bytes: number[] = []
        let v: number = Math.trunc(value)
        if (v >= 0) {
            do {
                bytes.unshift(v & 0xff)
                v = Math.floor(v / 256)
            } while (v > 0)
            if (bytes[0] & 0x80) bytes.unshift(0)
        } else {
            do {
                bytes.unshift(v & 0xff)
                v = Math.floor(v / 256)
            } while (v < -1)
            if (!(bytes[0] & 0x80)) bytes.unshift(0xff)
        }
        return Buffer.from(bytes)
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

    /** Build a complete TLV: tag + minimal length + content. */
    static #tlv(tag: number, content: Buffer): Buffer {
        return Buffer.concat([Buffer.from([tag]), this.#encodeLength(content.length), content])
    }

    /**
     * Peek the outer SEQUENCE header from a short prefix and return the whole-message length
     * (header bytes + declared content). The length field is read UNCLAMPED (the peek is only long
     * enough for the header, so #readTLV's content clamp would wrongly cap the total). Returns 0 when
     * the prefix does not open a well-formed SEQUENCE header.
     */
    static #outerMessageLength(peek: Buffer): number {
        if (peek.length < 2 || peek[0] !== 0x30) return 0
        let hp: number = 1
        let declaredLength: number = peek[hp]
        hp += 1
        if (declaredLength & 0x80) {
            const lengthBytes: number = declaredLength & 0x7f
            if (lengthBytes < 1 || lengthBytes > 4) return 0
            declaredLength = 0
            for (let i: number = 0; i < lengthBytes; i++) {
                declaredLength = declaredLength * 256 + (hp < peek.length ? peek[hp] : 0)
                hp += 1
            }
        }
        return hp + declaredLength
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'LDAP op=${protocolOpTag}',
            properties: {
                //LDAP is one nested BER blob, so the whole message is parsed here (and emitted in the
                //matching encode) rather than field-by-field at fixed offsets. The remaining properties
                //below carry only schema/label/validation metadata; they have no closures of their own.
                messageID: {
                    type: 'integer',
                    //A real LDAP messageID is 0..maxInt, but the on-wire field is a signed BER INTEGER, so a
                    //malformed frame can carry a negative value. The bounds match the signed 32-bit range the
                    //#berInt/#intToBer helpers support, so decode of a malformed negative messageID re-encodes
                    //faithfully instead of tripping the encode-entry Ajv gate (keeping decode→encode total).
                    minimum: -2147483648,
                    maximum: 2147483647,
                    decode: function (this: LDAP): void {
                        const available: number = this.packet.length - this.startPos
                        if (available <= 0) return
                        //Peek the outer SEQUENCE header to learn the whole-message length, then read the
                        //whole message (non-dry-run) so headerLength/endPos cover exactly the BER message.
                        const peek: Buffer = this.readBytes(0, available < 8 ? available : 8, true)
                        const declaredTotal: number = LDAP.#outerMessageLength(peek)
                        const total: number = Math.min(declaredTotal > 0 ? declaredTotal : available, available)
                        const buf: Buffer = this.readBytes(0, total > 0 ? total : 0)
                        const message: BerTLV = LDAP.#readTLV(buf, 0)
                        let p: number = message.contentStart
                        const messageIdTLV: BerTLV = LDAP.#readTLV(buf, p)
                        this.instance.messageID.setValue(LDAP.#berInt(buf.subarray(messageIdTLV.contentStart, messageIdTLV.next)))
                        p = messageIdTLV.next
                        //protocolOp: its TAG is one byte (e.g. 0x60 bindRequest); its BODY — the op's own
                        //length/content plus any trailing controls, all the way to the end of the outer
                        //SEQUENCE — is kept verbatim so any operation round-trips without a per-op encoder.
                        if (p >= message.next) return
                        this.instance.protocolOpTag.setValue(buf[p])
                        this.instance.protocolOpData.setValue(buf.subarray(p + 1, message.next).toString('hex'))
                    },
                    encode: function (this: LDAP): void {
                        const messageID: number = this.instance.messageID.getValue(0)
                        const protocolOpTag: number = this.instance.protocolOpTag.getValue(0x60)
                        const protocolOpData: string = this.instance.protocolOpData.getValue('')
                        const protocolOp: Buffer = Buffer.concat([
                            Buffer.from([protocolOpTag & 0xff]),
                            Buffer.from(protocolOpData, 'hex')
                        ])
                        const message: Buffer = LDAP.#tlv(0x30, Buffer.concat([
                            LDAP.#tlv(0x02, LDAP.#intToBer(messageID)),
                            protocolOp
                        ]))
                        this.writeBytes(0, message)
                    }
                },
                //The protocolOp CHOICE tag: 0x60 bindRequest, 0x61 bindResponse, 0x63 searchRequest,
                //0x64 searchResultEntry, 0x65 searchResultDone, 0x66 modifyRequest, 0x67 modifyResponse,
                //0x68 addRequest, 0x69 addResponse, 0x4a delRequest, 0x42 unbindRequest, 0x73 extendedReq …
                protocolOpTag: {type: 'integer', label: 'Protocol Op Tag', minimum: 0, maximum: 255},
                //The protocolOp body (op length/content + any controls) kept verbatim as hex — see decode.
                protocolOpData: {type: 'string', label: 'Protocol Op Data', contentEncoding: StringContentEncodingEnum.HEX}
            }
        }
    }

    public readonly id: string = 'ldap'

    public readonly name: string = 'LDAP'

    public readonly nickname: string = 'LDAP'

    //Directory service on TCP port 389. A BER SEQUENCE opening a message has only a weak content
    //signature (tag 0x30 + a plausible definite length, then an INTEGER messageID), so this is
    //port-defined: no heuristicFallback — the port + 0x30 signature is not distinctive enough to claim
    //arbitrary TCP segments, so LDAP is only tried on its well-known port.
    public readonly matchKeys: string[] = ['tcpport:389']

    public match(): boolean {
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        const available: number = this.packet.length - this.startPos
        if (available < 2) return false
        const peek: Buffer = this.readBytes(0, available < 8 ? available : 8, true)
        //Must open with a BER SEQUENCE (0x30) whose definite length is well-formed and plausible.
        if (peek[0] !== 0x30) return false
        const declaredTotal: number = LDAP.#outerMessageLength(peek)
        if (declaredTotal <= 0) return false
        //Locate the byte after the outer length; for a real LDAPMessage it is the messageID INTEGER
        //tag (0x02). This strengthens the otherwise-weak port+0x30 signature and rejects non-LDAP
        //SEQUENCE-like traffic on 389.
        let hp: number = 1
        const lenByte: number = peek[1]
        hp += 1
        if (lenByte & 0x80) hp += (lenByte & 0x7f)
        if (hp < peek.length && peek[hp] !== 0x02) return false
        return true
    }

    //A leaf header — nothing demuxes above LDAP in this minimal slice.
    public readonly demuxProducers: DemuxProducer[] = []

}
