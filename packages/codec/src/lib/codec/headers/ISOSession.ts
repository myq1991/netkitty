import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'

/**
 * ISO Session — the OSI Session layer (ISO 8327 / X.225) that sits above COTP in the MMS stack
 * (TPKT → COTP → Session → Presentation → MMS). Each SPDU is a 1-byte SI (SPDU Identifier) + 1-byte LI
 * (Length Indicator) + LI bytes of parameters. The MMS data phase is the fixed pair GIVE-TOKENS +
 * DATA-TRANSFER (`01 00 01 00`); the connection phase is a CONNECT (SI 13) or ACCEPT (SI 14) SPDU with
 * variable parameters.
 *
 * Session is decoded as a small chain of SPDUs (each SI/LI/params kept verbatim), then the user data —
 * the Presentation/MMS PDU that follows — is handed to the codec's dispatch (like COTP hands its payload
 * to Session). The single-frame completeness gate is already enforced upstream by COTP (it only exposes
 * a child for a DT+EOT PDU fully contained in the packet), so a T2-fragmented MMS body never reaches
 * here. The SPDU chain round-trips byte-for-byte; the presentation/MMS remainder is a child layer.
 */
export class ISOSession extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    //Session SPDU Identifiers we walk over: DT/GT (1), REFUSE (5), NOT-FINISHED (8), FINISH/DISCONNECT
    //(9), CONNECT (13), ACCEPT (14), ABORT (25), ABORT-ACCEPT (26). The Presentation PDU that follows
    //begins with a BER tag (0x61 / 0x31), which is not in this set, so the walk stops at the boundary.
    static #VALID_SI: Set<number> = new Set([1, 5, 8, 9, 13, 14, 25, 26])

    //ACSE (ISO 8650) APDU tags, for naming the connection-phase PDU carried inside a CONNECT/ACCEPT SPDU.
    static readonly #ACSE_NAMES: Record<number, string> = {
        0x60: 'AARQ', 0x61: 'AARE', 0x62: 'RLRQ', 0x63: 'RLRE', 0x64: 'ABRT'
    }

    public get SCHEMA(): ProtocolJSONSchema {
        return (ISOSession.#schemaCache ??= ISOSession.#buildSchema())
    }

    /** A clamping, never-throwing BER TLV read at `pos`: {tag, contentStart, contentLength} or null past end. */
    static #readTLV(buf: Buffer, pos: number): {tag: number, contentStart: number, contentLength: number} | null {
        if (pos + 2 > buf.length) return null
        const tag: number = buf[pos]
        const lengthOctet: number = buf[pos + 1]
        let contentStart: number = pos + 2
        let contentLength: number
        if (lengthOctet < 0x80) {
            contentLength = lengthOctet
        } else if (lengthOctet === 0x80) {
            contentLength = buf.length - contentStart //indefinite: run to end (kept verbatim)
        } else {
            const n: number = lengthOctet & 0x7f
            if (contentStart + n > buf.length) return null
            contentLength = 0
            for (let i: number = 0; i < n; i++) contentLength = (contentLength << 8) | buf[contentStart + i]
            contentStart += n
        }
        if (contentStart + contentLength > buf.length) contentLength = buf.length - contentStart
        if (contentLength < 0) contentLength = 0
        return {tag: tag, contentStart: contentStart, contentLength: contentLength}
    }

    /** Find the first direct child TLV with the given tag within [start, end). */
    static #findChild(buf: Buffer, start: number, end: number, wantTag: number): {tag: number, contentStart: number, contentLength: number} | null {
        let pos: number = start
        while (pos < end) {
            const tlv: {tag: number, contentStart: number, contentLength: number} | null = ISOSession.#readTLV(buf, pos)
            if (!tlv) break
            if (tlv.tag === wantTag) return tlv
            const next: number = tlv.contentStart + tlv.contentLength
            if (next <= pos) break
            pos = next
        }
        return null
    }

    /** Locate the SS-user-data (PGI 0xc1 / extended 0xc2) inside a CONNECT/ACCEPT SPDU's ISO 8327 params. */
    static #sessionUserData(params: Buffer): Buffer | null {
        let pos: number = 0
        while (pos + 2 <= params.length) {
            const pi: number = params[pos]
            let li: number = params[pos + 1]
            let contentStart: number = pos + 2
            if (li === 0xff) {
                if (contentStart + 2 > params.length) break
                li = (params[contentStart] << 8) | params[contentStart + 1]
                contentStart += 2
            }
            if (pi === 0xc1 || pi === 0xc2) {
                const end: number = Math.min(contentStart + li, params.length)
                return params.subarray(contentStart, end)
            }
            const next: number = contentStart + li
            if (next <= pos) break
            pos = next
        }
        return null
    }

    /**
     * Detect the ACSE APDU inside a CONNECT/ACCEPT SPDU's user data (best-effort, never-throwing):
     * the ISO 8823 Presentation CP-type/CPA-type (0x31) → normal-mode-parameters [2] (0xa2) →
     * fully-encoded-data (0x61) → PDV-list (0x30) → presentation-data-values [0] (0xa0) → the ACSE APDU.
     * Returns the ACSE TLV (tag 0x60 AARQ … 0x64 ABRT) or null.
     */
    static #detectAcse(userData: Buffer): {tag: number, contentStart: number, contentLength: number} | null {
        const cp: {tag: number, contentStart: number, contentLength: number} | null = ISOSession.#readTLV(userData, 0)
        if (!cp || cp.tag !== 0x31) return null
        const nmp: {tag: number, contentStart: number, contentLength: number} | null =
            ISOSession.#findChild(userData, cp.contentStart, cp.contentStart + cp.contentLength, 0xa2)
        if (!nmp) return null
        const fed: {tag: number, contentStart: number, contentLength: number} | null =
            ISOSession.#findChild(userData, nmp.contentStart, nmp.contentStart + nmp.contentLength, 0x61)
        if (!fed) return null
        const pdv: {tag: number, contentStart: number, contentLength: number} | null = ISOSession.#readTLV(userData, fed.contentStart)
        if (!pdv || pdv.tag !== 0x30) return null
        const values: {tag: number, contentStart: number, contentLength: number} | null =
            ISOSession.#findChild(userData, pdv.contentStart, pdv.contentStart + pdv.contentLength, 0xa0)
        if (!values || values.contentStart >= userData.length) return null
        //Only report a genuine ACSE APDU (AARQ 0x60 … ABRT 0x64); anything else leaves acseType unset.
        const tag: number = userData[values.contentStart]
        if (!(tag >= 0x60 && tag <= 0x64)) return null
        return ISOSession.#readTLV(userData, values.contentStart)
    }

    /**
     * The OID inside a context-tagged ACSE field (e.g. application-context-name [1] = 0xa1, called-AP-title
     * [2] = 0xa2, responding-AP-title [4] = 0xa4, calling-AP-title [6] = 0xa6, each wrapping an OBJECT
     * IDENTIFIER form) as a dotted string, or ''.
     */
    static #acseOid(buf: Buffer, acse: {contentStart: number, contentLength: number}, wantTag: number): string {
        const field: {tag: number, contentStart: number, contentLength: number} | null =
            ISOSession.#findChild(buf, acse.contentStart, acse.contentStart + acse.contentLength, wantTag)
        if (!field) return ''
        const oid: {tag: number, contentStart: number, contentLength: number} | null = ISOSession.#readTLV(buf, field.contentStart)
        if (!oid || oid.tag !== 0x06) return ''
        return ISOSession.#decodeOid(buf, oid.contentStart, oid.contentLength)
    }

    /** Read a small INTEGER (≤ 6 octets) from the first direct child with `wantTag` within [start, end), or -1. */
    static #acseInt(buf: Buffer, start: number, end: number, wantTag: number): number {
        const tlv: {tag: number, contentStart: number, contentLength: number} | null = ISOSession.#findChild(buf, start, end, wantTag)
        if (!tlv) return -1
        let value: number = 0
        const limit: number = Math.min(tlv.contentLength, 6)
        for (let i: number = 0; i < limit; i++) value = (value * 256) + buf[tlv.contentStart + i]
        return value
    }

    /**
     * Extract the MMS initiate parameters carried in the ACSE user-information (best-effort, never-throwing):
     * ACSE user-information [30] (0xbe) → EXTERNAL (0x28) → encoding [0] (0xa0) → MMS initiate PDU (0xa8
     * request / 0xa9 response) → proposedMaxServOutstandingCalling [1], -Called [2], nesting-level [3], and
     * the (proposed/negotiated) version number inside init-detail [4] → [0]. -1 for any absent part.
     */
    static #mmsInitiate(buf: Buffer, acse: {contentStart: number, contentLength: number}): {maxCalling: number, maxCalled: number, nesting: number, version: number} {
        const out: {maxCalling: number, maxCalled: number, nesting: number, version: number} = {maxCalling: -1, maxCalled: -1, nesting: -1, version: -1}
        const ui: {tag: number, contentStart: number, contentLength: number} | null =
            ISOSession.#findChild(buf, acse.contentStart, acse.contentStart + acse.contentLength, 0xbe)
        if (!ui) return out
        const ext: {tag: number, contentStart: number, contentLength: number} | null =
            ISOSession.#findChild(buf, ui.contentStart, ui.contentStart + ui.contentLength, 0x28)
        if (!ext) return out
        const enc: {tag: number, contentStart: number, contentLength: number} | null =
            ISOSession.#findChild(buf, ext.contentStart, ext.contentStart + ext.contentLength, 0xa0)
        if (!enc) return out
        const init: {tag: number, contentStart: number, contentLength: number} | null = ISOSession.#readTLV(buf, enc.contentStart)
        if (!init || (init.tag !== 0xa8 && init.tag !== 0xa9)) return out
        const end: number = init.contentStart + init.contentLength
        out.maxCalling = ISOSession.#acseInt(buf, init.contentStart, end, 0x81)
        out.maxCalled = ISOSession.#acseInt(buf, init.contentStart, end, 0x82)
        out.nesting = ISOSession.#acseInt(buf, init.contentStart, end, 0x83)
        const detail: {tag: number, contentStart: number, contentLength: number} | null =
            ISOSession.#findChild(buf, init.contentStart, end, 0xa4)
        if (detail) out.version = ISOSession.#acseInt(buf, detail.contentStart, detail.contentStart + detail.contentLength, 0x80)
        return out
    }

    /** Decode a BER OBJECT IDENTIFIER body to a dotted string (never-throwing, clamped). */
    static #decodeOid(buf: Buffer, start: number, length: number): string {
        if (length <= 0 || start + length > buf.length) return ''
        //Accumulate base-128 subidentifiers (high-bit continuation). Multiplication (not <<7) so arcs above
        //2^28 don't overflow the 32-bit shift.
        const subs: number[] = []
        let value: number = 0
        for (let i: number = start; i < start + length; i++) {
            value = value * 128 + (buf[i] & 0x7f)
            if ((buf[i] & 0x80) === 0) {
                subs.push(value)
                value = 0
            }
        }
        if (subs.length === 0) return ''
        //The first subidentifier encodes the first two arcs: X*40 + Y, X in {0,1,2} (Y unbounded when X=2).
        const first: number = subs[0]
        const x: number = first < 40 ? 0 : first < 80 ? 1 : 2
        const parts: number[] = [x, first - x * 40, ...subs.slice(1)]
        return parts.join('.')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'ISO-Session ${spdus.length} spdu',
            properties: {
                spdus: {
                    type: 'array',
                    label: 'SPDUs',
                    items: {
                        type: 'object',
                        properties: {
                            si: {type: 'integer', label: 'SPDU Identifier', minimum: 0, maximum: 255},
                            li: {type: 'integer', label: 'Length Indicator', minimum: 0, maximum: 255},
                            params: {type: 'string', label: 'Parameters', contentEncoding: 'hex'}
                        }
                    },
                    decode: function (this: ISOSession): void {
                        const available: number = this.packet.length - this.startPos
                        const spdus: {si: number, li: number, params: string}[] = []
                        let offset: number = 0
                        //Walk SPDUs while the SI is a session identifier; stop at the Presentation PDU (a
                        //BER tag, not a session SI). The SI/LI are peeked dryRun so a malformed length
                        //leaves the bytes to the child rather than being mis-consumed.
                        while (offset + 2 <= available) {
                            const si: number = this.readBytes(offset, 1, true)[0]
                            if (!ISOSession.#VALID_SI.has(si)) break
                            const li: number = this.readBytes(offset + 1, 1, true)[0]
                            if (offset + 2 + li > available) break
                            const params: string = li > 0 ? BufferToHex(this.readBytes(offset + 2, li, true)) : ''
                            spdus.push({si: si, li: li, params: params})
                            offset += 2 + li
                        }
                        //Mark the consumed SPDU region so headerLength stops here and the codec dispatches
                        //the Presentation/MMS remainder as a child (empty-param SPDUs do no non-dry read).
                        if (offset > 0) this.readBytes(0, offset)
                        this.instance.spdus.setValue(spdus)
                        //Connection phase: a CONNECT (13) / ACCEPT (14) SPDU embeds the ACSE APDU in its
                        //user data (the presentation is not a following child here). Surface its type for
                        //display; the params stay verbatim so the byte round-trip is unaffected.
                        for (const spdu of spdus) {
                            if (spdu.si !== 13 && spdu.si !== 14) continue
                            const userData: Buffer | null = ISOSession.#sessionUserData(HexToBuffer(spdu.params))
                            if (!userData) continue
                            const acse: {tag: number, contentStart: number, contentLength: number} | null = ISOSession.#detectAcse(userData)
                            if (acse) {
                                this.instance.acseType.setValue(ISOSession.#ACSE_NAMES[acse.tag] ?? `0x${acse.tag.toString(16)}`)
                                const appContext: string = ISOSession.#acseOid(userData, acse, 0xa1)
                                if (appContext) this.instance.acseAppContext.setValue(appContext)
                                if (acse.tag === 0x60) {
                                    //AARQ: called-AP-title [2], calling-AP-title [6].
                                    const called: string = ISOSession.#acseOid(userData, acse, 0xa2)
                                    if (called) this.instance.acseCalledApTitle.setValue(called)
                                    const calling: string = ISOSession.#acseOid(userData, acse, 0xa6)
                                    if (calling) this.instance.acseCallingApTitle.setValue(calling)
                                } else if (acse.tag === 0x61) {
                                    //AARE: responding-AP-title [4].
                                    const responding: string = ISOSession.#acseOid(userData, acse, 0xa4)
                                    if (responding) this.instance.acseRespondingApTitle.setValue(responding)
                                }
                                //MMS initiate parameters carried in the ACSE user-information.
                                const init: {maxCalling: number, maxCalled: number, nesting: number, version: number} = ISOSession.#mmsInitiate(userData, acse)
                                if (init.maxCalling >= 0) this.instance.mmsInitMaxServOutstandingCalling.setValue(init.maxCalling)
                                if (init.maxCalled >= 0) this.instance.mmsInitMaxServOutstandingCalled.setValue(init.maxCalled)
                                if (init.nesting >= 0) this.instance.mmsInitNestingLevel.setValue(init.nesting)
                                if (init.version >= 0) this.instance.mmsInitVersion.setValue(init.version)
                            }
                            break
                        }
                    },
                    encode: function (this: ISOSession): void {
                        const spdus: any[] | undefined = this.instance.spdus.getValue()
                        if (!Array.isArray(spdus)) return
                        let offset: number = 0
                        for (const spdu of spdus) {
                            const si: number = Number(spdu && spdu.si) & 0xff
                            const params: Buffer = HexToBuffer(spdu && spdu.params ? String(spdu.params) : '')
                            //LI honored when supplied (a crafted SPDU may lie), else derived from params.
                            const provided: number = Number(spdu && spdu.li)
                            const li: number = (spdu && spdu.li !== undefined && spdu.li !== null && Number.isFinite(provided)) ? provided & 0xff : params.length & 0xff
                            this.writeBytes(offset, Buffer.from([si, li]))
                            if (params.length) this.writeBytes(offset + 2, params)
                            offset += 2 + params.length
                        }
                    }
                },
                //Display-only: the ACSE APDU type (AARQ/AARE/…) and application-context-name OID parsed from
                //a CONNECT/ACCEPT SPDU's user data on decode. No encode closure — the SPDU params above stay
                //the encode authority.
                acseType: {type: 'string', label: 'ACSE APDU'},
                acseAppContext: {type: 'string', label: 'ACSE Application Context'},
                acseCalledApTitle: {type: 'string', label: 'ACSE Called AP-Title'},
                acseCallingApTitle: {type: 'string', label: 'ACSE Calling AP-Title'},
                acseRespondingApTitle: {type: 'string', label: 'ACSE Responding AP-Title'},
                mmsInitMaxServOutstandingCalling: {type: 'integer', label: 'MMS Init Max Serv Outstanding Calling'},
                mmsInitMaxServOutstandingCalled: {type: 'integer', label: 'MMS Init Max Serv Outstanding Called'},
                mmsInitNestingLevel: {type: 'integer', label: 'MMS Init Data Structure Nesting Level'},
                mmsInitVersion: {type: 'integer', label: 'MMS Init Version'}
            }
        }
    }

    public readonly id: string = 'iso-session'

    public readonly name: string = 'ISO Session'

    public readonly nickname: string = 'ISO-SES'

    //A content-heuristic child of COTP (unkeyed), selected by a session SI at the start of the COTP payload.
    public readonly matchKeys: string[] = []

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        const prev: any = this.prevCodecModule
        if (!prev || prev.id !== 'cotp') return false
        if (this.packet.length - this.startPos < 2) return false
        return ISOSession.#VALID_SI.has(this.readBytes(0, 1, true)[0])
    }

    //The Presentation/MMS PDU follows as a child — nothing demuxes off Session by a field value.
    public readonly demuxProducers: DemuxProducer[] = []

}
