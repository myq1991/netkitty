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

    public get SCHEMA(): ProtocolJSONSchema {
        return (ISOSession.#schemaCache ??= ISOSession.#buildSchema())
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
                }
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
