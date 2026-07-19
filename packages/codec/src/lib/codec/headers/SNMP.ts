import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** One parsed BER TLV within a buffer: its tag byte, where its content starts, its length, and the offset just past it. */
type BerTLV = {tag: number, contentStart: number, contentLen: number, next: number}

/** One SNMP variable binding: an object identifier and its value (kept by BER type + verbatim hex). */
type SnmpVarBind = {oid: string, valueType: number, value: string}

/**
 * SNMP — Simple Network Management Protocol v1 / v2c (RFC 1157 / RFC 3416). The message is a single
 * ASN.1 BER structure: SEQUENCE { version INTEGER, community OCTET STRING, PDU }, where the PDU is a
 * context tag ([0]=get-request … [2]=get-response/response, [3]=set-request, [5]=get-bulk-request,
 * [7]=snmpV2-trap …) wrapping SEQUENCE { request-id, error-status, error-index, variable-bindings }.
 * Rides UDP ports 161 (agent) and 162 (trap).
 *
 * Byte-perfect strategy: the four INTEGER fields are decoded as signed integers and re-emitted with
 * minimal two's-complement BER; the object identifier is decoded to a dotted string and re-emitted via
 * base-128 sub-identifiers; community is kept as a latin1 string; and each binding's VALUE is kept as
 * its BER tag + verbatim hex content (so any value type — OctetString, TimeTicks, Counter, IpAddress,
 * Null … — round-trips exactly without needing a per-type encoder). Definite lengths are re-derived in
 * minimal form, matching the standard DER-style encoding SNMP agents emit. SNMPv3 (which adds security
 * parameters and optional encryption) is a later, separate concern.
 */
export class SNMP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    //The PDU tags that share the RFC 3416 body shape {request-id, error-status, error-index, varbinds}:
    //get-request(0xa0), get-next(0xa1), get-response(0xa2), set-request(0xa3), get-bulk(0xa5),
    //inform(0xa6), snmpV2-trap(0xa7), report(0xa8). The SNMPv1 Trap-PDU (0xa4) has a DIFFERENT body
    //(enterprise/agent-addr/generic/specific/timestamp/varbinds), so it — and any unknown tag — is kept
    //verbatim (pduRaw) rather than misparsed, preserving a byte-perfect round-trip.
    static readonly #RFC3416_PDU_TAGS: ReadonlySet<number> = new Set([0xa0, 0xa1, 0xa2, 0xa3, 0xa5, 0xa6, 0xa7, 0xa8])

    public get SCHEMA(): ProtocolJSONSchema {
        return (SNMP.#schemaCache ??= SNMP.#buildSchema())
    }

    // ===== Minimal BER/DER codec (definite length only) =====

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

    /** Decode a BER OBJECT IDENTIFIER content into a dotted string. */
    static #oidToStr(buf: Buffer): string {
        const subs: number[] = []
        let value: number = 0
        for (let i: number = 0; i < buf.length; i++) {
            value = value * 128 + (buf[i] & 0x7f)
            if (!(buf[i] & 0x80)) {
                subs.push(value)
                value = 0
            }
        }
        if (subs.length === 0) return ''
        const first: number = subs[0]
        const arc0: number = first < 80 ? Math.floor(first / 40) : 2
        const arc1: number = first - arc0 * 40
        return [arc0, arc1, ...subs.slice(1)].join('.')
    }

    /** Encode a dotted OID string into BER OBJECT IDENTIFIER content bytes (base-128 sub-identifiers). */
    static #strToOid(oid: string): Buffer {
        const arcs: number[] = oid.split('.').map((arc: string): number => Number(arc) || 0)
        const subs: number[] = []
        if (arcs.length >= 2) subs.push(arcs[0] * 40 + arcs[1])
        else if (arcs.length === 1) subs.push(arcs[0] * 40)
        for (let i: number = 2; i < arcs.length; i++) subs.push(arcs[i])
        const bytes: number[] = []
        for (const sub of subs) {
            const group: number[] = []
            let v: number = sub
            do {
                group.unshift(v & 0x7f)
                v = Math.floor(v / 128)
            } while (v > 0)
            for (let i: number = 0; i < group.length - 1; i++) group[i] |= 0x80
            bytes.push(...group)
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

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SNMP ${community} req=${requestId}',
            properties: {
                //SNMP is one nested BER blob, so the whole message is parsed here (and emitted in the
                //matching encode) rather than field-by-field at fixed offsets. The remaining properties
                //below carry only schema/label/validation metadata; they have no closures of their own.
                version: {
                    type: 'integer',
                    label: 'Version',
                    minimum: 0,
                    maximum: 3,
                    decode: function (this: SNMP): void {
                        const available: number = this.packet.length - this.startPos
                        if (available <= 0) return
                        //Peek the outer SEQUENCE header to learn the whole-message length (the length
                        //field is read UNCLAMPED here — the peek is only long enough for the header, so
                        //#readTLV's content clamp would wrongly cap the total), then read the whole
                        //message (non-dry-run) so headerLength/endPos cover exactly the BER message.
                        const peek: Buffer = this.readBytes(0, available < 8 ? available : 8, true)
                        let hp: number = 1
                        let declaredLength: number = hp < peek.length ? peek[hp] : 0
                        hp += 1
                        if (declaredLength & 0x80) {
                            const lengthBytes: number = declaredLength & 0x7f
                            declaredLength = 0
                            for (let i: number = 0; i < lengthBytes; i++) {
                                declaredLength = declaredLength * 256 + (hp < peek.length ? peek[hp] : 0)
                                hp += 1
                            }
                        }
                        const total: number = Math.min(hp + declaredLength, available)
                        const buf: Buffer = this.readBytes(0, total > 0 ? total : 0)
                        const message: BerTLV = SNMP.#readTLV(buf, 0)
                        let p: number = message.contentStart
                        const versionTLV: BerTLV = SNMP.#readTLV(buf, p)
                        this.instance.version.setValue(SNMP.#berInt(buf.subarray(versionTLV.contentStart, versionTLV.next)))
                        p = versionTLV.next
                        const communityTLV: BerTLV = SNMP.#readTLV(buf, p)
                        this.instance.community.setValue(buf.subarray(communityTLV.contentStart, communityTLV.next).toString('latin1'))
                        p = communityTLV.next
                        const pduTLV: BerTLV = SNMP.#readTLV(buf, p)
                        this.instance.pduType.setValue(pduTLV.tag)
                        if (!SNMP.#RFC3416_PDU_TAGS.has(pduTLV.tag)) {
                            //Non-RFC-3416 PDU (SNMPv1 Trap 0xa4, or an unknown tag): keep the body bytes
                            //verbatim so it round-trips exactly. Structured fields are left unset;
                            //semantic decoding of the v1 trap body is a later enrichment.
                            this.instance.pduRaw.setValue(buf.subarray(pduTLV.contentStart, pduTLV.next).toString('hex'))
                            return
                        }
                        let pp: number = pduTLV.contentStart
                        const requestIdTLV: BerTLV = SNMP.#readTLV(buf, pp)
                        this.instance.requestId.setValue(SNMP.#berInt(buf.subarray(requestIdTLV.contentStart, requestIdTLV.next)))
                        pp = requestIdTLV.next
                        const errorStatusTLV: BerTLV = SNMP.#readTLV(buf, pp)
                        this.instance.errorStatus.setValue(SNMP.#berInt(buf.subarray(errorStatusTLV.contentStart, errorStatusTLV.next)))
                        pp = errorStatusTLV.next
                        const errorIndexTLV: BerTLV = SNMP.#readTLV(buf, pp)
                        this.instance.errorIndex.setValue(SNMP.#berInt(buf.subarray(errorIndexTLV.contentStart, errorIndexTLV.next)))
                        pp = errorIndexTLV.next
                        const bindingsTLV: BerTLV = SNMP.#readTLV(buf, pp)
                        const varbinds: SnmpVarBind[] = []
                        let vp: number = bindingsTLV.contentStart
                        while (vp < bindingsTLV.next && vp < buf.length) {
                            const bindTLV: BerTLV = SNMP.#readTLV(buf, vp)
                            let ip: number = bindTLV.contentStart
                            const oidTLV: BerTLV = SNMP.#readTLV(buf, ip)
                            const oid: string = SNMP.#oidToStr(buf.subarray(oidTLV.contentStart, oidTLV.next))
                            ip = oidTLV.next
                            const valueTLV: BerTLV = SNMP.#readTLV(buf, ip)
                            varbinds.push({
                                oid: oid,
                                valueType: valueTLV.tag,
                                value: buf.subarray(valueTLV.contentStart, valueTLV.next).toString('hex')
                            })
                            vp = bindTLV.next
                        }
                        this.instance.variableBindings.setValue(varbinds)
                    },
                    encode: function (this: SNMP): void {
                        const version: number = this.instance.version.getValue(0)
                        const community: string = this.instance.community.getValue('')
                        const pduType: number = this.instance.pduType.getValue(0xa0)
                        const requestId: number = this.instance.requestId.getValue(0)
                        const errorStatus: number = this.instance.errorStatus.getValue(0)
                        const errorIndex: number = this.instance.errorIndex.getValue(0)
                        const pduRaw: string = this.instance.pduRaw.getValue('')
                        let pduContent: Buffer
                        if (pduRaw) {
                            //A non-RFC-3416 PDU kept verbatim (e.g. SNMPv1 trap): re-emit its body as-is.
                            pduContent = Buffer.from(pduRaw, 'hex')
                        } else {
                            const varbinds: SnmpVarBind[] = this.instance.variableBindings.getValue([])
                            const bindBuffers: Buffer[] = (varbinds ? varbinds : []).map((varbind: SnmpVarBind): Buffer => {
                                const oidBuffer: Buffer = SNMP.#tlv(0x06, SNMP.#strToOid(varbind.oid ? varbind.oid : ''))
                                const valueBuffer: Buffer = SNMP.#tlv(varbind.valueType ? varbind.valueType : 0x05, Buffer.from(varbind.value ? varbind.value : '', 'hex'))
                                return SNMP.#tlv(0x30, Buffer.concat([oidBuffer, valueBuffer]))
                            })
                            pduContent = Buffer.concat([
                                SNMP.#tlv(0x02, SNMP.#intToBer(requestId)),
                                SNMP.#tlv(0x02, SNMP.#intToBer(errorStatus)),
                                SNMP.#tlv(0x02, SNMP.#intToBer(errorIndex)),
                                SNMP.#tlv(0x30, Buffer.concat(bindBuffers))
                            ])
                        }
                        const message: Buffer = SNMP.#tlv(0x30, Buffer.concat([
                            SNMP.#tlv(0x02, SNMP.#intToBer(version)),
                            SNMP.#tlv(0x04, Buffer.from(community, 'latin1')),
                            SNMP.#tlv(pduType, pduContent)
                        ]))
                        this.writeBytes(0, message)
                    }
                },
                community: {type: 'string', label: 'Community'},
                //The PDU context tag: 0xa0 get-request, 0xa1 get-next-request, 0xa2 get-response,
                //0xa3 set-request, 0xa5 get-bulk-request, 0xa6 inform-request, 0xa7 snmpV2-trap, 0xa8 report.
                pduType: {type: 'integer', label: 'PDU Type', minimum: 0, maximum: 255},
                //Verbatim PDU body for non-RFC-3416 PDUs (SNMPv1 Trap 0xa4 / unknown tags). Hidden and
                //empty for the common request/response PDUs, which use the structured fields below.
                pduRaw: {type: 'string', label: 'PDU Body', contentEncoding: StringContentEncodingEnum.HEX, hidden: true},
                requestId: {type: 'integer', label: 'Request ID'},
                errorStatus: {type: 'integer', label: 'Error Status', minimum: 0},
                errorIndex: {type: 'integer', label: 'Error Index', minimum: 0},
                variableBindings: {
                    type: 'array',
                    label: 'Variable Bindings',
                    items: {
                        type: 'object',
                        label: 'Variable Binding',
                        properties: {
                            oid: {type: 'string', label: 'Object Identifier'},
                            valueType: {type: 'integer', label: 'Value Type', minimum: 0, maximum: 255},
                            value: {type: 'string', label: 'Value', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'snmp'

    public readonly name: string = 'Simple Network Management Protocol'

    public readonly nickname: string = 'SNMP'

    //Agent port 161, trap/notification port 162 (both UDP). BER SEQUENCE has no reliable content
    //signature, so this is port-defined (no heuristicFallback).
    public readonly matchKeys: string[] = ['udpport:161', 'udpport:162']

    public match(): boolean {
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp'
    }

    //A leaf header — nothing demuxes above SNMP.
    public readonly demuxProducers: DemuxProducer[] = []

}
