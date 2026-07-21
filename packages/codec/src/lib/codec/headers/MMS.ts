import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'

/**
 * MMS — Manufacturing Message Specification (ISO 9506) for IEC 61850, the innermost application layer of
 * the substation stack: TPKT → COTP → ISO Session → (this) ISO Presentation + MMS. In the data-transfer
 * phase the Session user data is a Presentation "fully-encoded-data" PDU (BER `[APPLICATION 1]`, tag
 * 0x61) that wraps a PDV-list (SEQUENCE 0x30) carrying a presentation-context-identifier and the MMS PDU
 * itself as `[0]` single-ASN1-type (0xa0). The MMS PDU is a CHOICE — 0xa0 confirmed-request, 0xa1
 * confirmed-response, 0xa2 confirmed-error, 0xa3 unconfirmed, 0xa8 initiate-request, 0xa9
 * initiate-response, 0x05 NULL (keep-alive) …
 *
 * Following the SNMP pattern, this header owns the whole nested BER blob and re-emits it verbatim (so it
 * round-trips byte-for-byte regardless of definite/indefinite length quirks), while exposing the parsed
 * presentation context and the MMS PDU type as display metadata. The single-frame completeness gate is
 * enforced upstream by COTP, so a T2-fragmented MMS body never reaches here. Deeper structuring of the
 * MMS service body (read/write/report) and the connection-phase ACSE are later slices.
 */
export class MMS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (MMS.#schemaCache ??= MMS.#buildSchema())
    }

    /**
     * A clamping, never-throwing BER TLV read at `pos`: returns the tag, the header length (tag+length
     * octets), the content start and the content length (clamped to the buffer). Indefinite length (0x80)
     * yields a content that runs to the buffer end (kept verbatim, not parsed). Returns null past the end.
     */
    static #readTLV(buf: Buffer, pos: number): {tag: number, contentStart: number, contentLength: number} | null {
        if (pos + 2 > buf.length) return null
        const tag: number = buf[pos]
        let lengthOctet: number = buf[pos + 1]
        let contentStart: number = pos + 2
        let contentLength: number
        if (lengthOctet < 0x80) {
            contentLength = lengthOctet
        } else if (lengthOctet === 0x80) {
            contentLength = buf.length - contentStart
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

    //MMS ConfirmedServiceRequest/Response CHOICE context tags (ISO 9506-2) → service name, for display.
    static readonly #SERVICE_NAMES: Record<number, string> = {
        0: 'status', 1: 'getNameList', 2: 'identify', 3: 'rename', 4: 'read', 5: 'write',
        6: 'getVariableAccessAttributes', 7: 'defineNamedVariable', 8: 'defineScatteredAccess',
        9: 'getScatteredAccessAttributes', 10: 'deleteVariableAccess', 11: 'defineNamedVariableList',
        12: 'getNamedVariableListAttributes', 13: 'deleteNamedVariableList', 14: 'defineNamedType',
        15: 'getNamedTypeAttributes', 16: 'deleteNamedType', 17: 'input', 18: 'output', 19: 'takeControl',
        20: 'relinquishControl', 21: 'defineSemaphore', 22: 'deleteSemaphore', 23: 'reportSemaphoreStatus',
        24: 'reportPoolSemaphoreStatus', 25: 'reportSemaphoreEntryStatus', 26: 'initiateDownloadSequence',
        27: 'downloadSegment', 28: 'terminateDownloadSequence', 29: 'initiateUploadSequence', 30: 'uploadSegment'
    }

    /**
     * Parse the Presentation/MMS nesting for display, best-effort: the presentation context, the MMS PDU
     * type (0xa0 confirmed-request / 0xa1 confirmed-response / 0xa2 confirmed-error / 0xa3 unconfirmed /
     * 0x05 NULL …), and — for a confirmed request/response/error — the invokeID and the service (from the
     * ConfirmedService CHOICE context tag). -1 / '' when a part is absent.
     */
    static #parse(buf: Buffer): {presentationContext: number, mmsPduType: number, invokeID: number, service: string} {
        const result: {presentationContext: number, mmsPduType: number, invokeID: number, service: string} =
            {presentationContext: -1, mmsPduType: -1, invokeID: -1, service: ''}
        //61 (fully-encoded-data) → 30 (PDV-list) → 02 01 ctx, a0 (presentation-data-values) → MMS PDU.
        const app: {tag: number, contentStart: number, contentLength: number} | null = MMS.#readTLV(buf, 0)
        if (!app || app.tag !== 0x61) return result
        const pdvList: {tag: number, contentStart: number, contentLength: number} | null = MMS.#readTLV(buf, app.contentStart)
        if (!pdvList || pdvList.tag !== 0x30) return result
        let pos: number = pdvList.contentStart
        const end: number = pdvList.contentStart + pdvList.contentLength
        while (pos < end) {
            const tlv: {tag: number, contentStart: number, contentLength: number} | null = MMS.#readTLV(buf, pos)
            if (!tlv) break
            if (tlv.tag === 0x02 && tlv.contentLength >= 1) {
                //presentation-context-identifier (INTEGER)
                let value: number = 0
                for (let i: number = 0; i < tlv.contentLength; i++) value = (value << 8) | buf[tlv.contentStart + i]
                result.presentationContext = value
            } else if (tlv.tag === 0xa0) {
                //presentation-data-values [0] → the MMS PDU TLV is inside.
                const mmsPdu: {tag: number, contentStart: number, contentLength: number} | null = MMS.#readTLV(buf, tlv.contentStart)
                if (mmsPdu) {
                    result.mmsPduType = mmsPdu.tag
                    MMS.#parseConfirmed(buf, mmsPdu, result)
                }
            }
            pos = tlv.contentStart + tlv.contentLength
        }
        return result
    }

    /** For a confirmed-request/response/error MMS PDU, extract the invokeID and the service name. */
    static #parseConfirmed(
        buf: Buffer,
        mmsPdu: {tag: number, contentStart: number, contentLength: number},
        result: {invokeID: number, service: string}
    ): void {
        if (mmsPdu.tag !== 0xa0 && mmsPdu.tag !== 0xa1 && mmsPdu.tag !== 0xa2) return
        //All three begin with the invokeID INTEGER (Confirmed-{Request,Response,Error}PDU).
        const invokeID: {tag: number, contentStart: number, contentLength: number} | null = MMS.#readTLV(buf, mmsPdu.contentStart)
        if (!invokeID || invokeID.tag !== 0x02) return
        let id: number = 0
        for (let i: number = 0; i < invokeID.contentLength; i++) id = (id << 8) | buf[invokeID.contentStart + i]
        result.invokeID = id
        //The ConfirmedService CHOICE is the element after the invokeID ONLY for request/response. A
        //Confirmed-ErrorPDU's second element is modifierPosition/serviceError, not a service, so skip it.
        if (mmsPdu.tag !== 0xa0 && mmsPdu.tag !== 0xa1) return
        const service: {tag: number, contentStart: number, contentLength: number} | null =
            MMS.#readTLV(buf, invokeID.contentStart + invokeID.contentLength)
        if (!service) return
        //Single-byte context tags (0..30) identify the service; a higher (multi-byte) tag's first byte has
        //low bits 0x1f=31, absent from the map, so it shows as "31" — lossy but never aliases a real name.
        const tagNumber: number = service.tag & 0x1f
        result.service = MMS.#SERVICE_NAMES[tagNumber] ?? String(tagNumber)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'MMS pdu=${mmsPduType} ctx=${presentationContext}',
            properties: {
                //The whole Presentation + MMS BER blob is the authoritative source: decoded verbatim to hex
                //and re-emitted untouched, so any (even malformed) frame round-trips byte-for-byte.
                message: {
                    type: 'string', label: 'Message', contentEncoding: 'hex',
                    decode: function (this: MMS): void {
                        const available: number = this.packet.length - this.startPos
                        const buf: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(buf))
                        const parsed: {presentationContext: number, mmsPduType: number, invokeID: number, service: string} = MMS.#parse(buf)
                        this.instance.presentationContext.setValue(parsed.presentationContext)
                        this.instance.mmsPduType.setValue(parsed.mmsPduType)
                        if (parsed.invokeID >= 0) this.instance.mmsInvokeID.setValue(parsed.invokeID)
                        if (parsed.service) this.instance.mmsService.setValue(parsed.service)
                    },
                    encode: function (this: MMS): void {
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the BER blob on decode (no encode — populated by the
                //message field above), so they never affect the re-emitted bytes. invokeID / service are
                //present only for a confirmed request/response/error PDU.
                presentationContext: {type: 'integer', label: 'Presentation Context'},
                mmsPduType: {type: 'integer', label: 'MMS PDU Type'},
                mmsInvokeID: {type: 'integer', label: 'Invoke ID'},
                mmsService: {type: 'string', label: 'MMS Service'}
            }
        }
    }

    public readonly id: string = 'mms'

    public readonly name: string = 'Manufacturing Message Specification'

    public readonly nickname: string = 'MMS'

    //A content-heuristic child of ISO Session (unkeyed), selected by the Presentation fully-encoded-data
    //BER tag 0x61 (the MMS data-transfer phase).
    public readonly matchKeys: string[] = []

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        const prev: any = this.prevCodecModule
        if (!prev || prev.id !== 'iso-session') return false
        if (this.packet.length - this.startPos < 2) return false
        //Presentation fully-encoded-data (BER [APPLICATION 1] = 0x61). The connection-phase CP-type (0x31)
        //+ ACSE is a later slice.
        return this.readBytes(0, 1, true)[0] === 0x61
    }

    //A leaf for this slice — the MMS service body is kept verbatim inside `message`.
    public readonly demuxProducers: DemuxProducer[] = []

}
