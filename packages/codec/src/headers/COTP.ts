import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt8} from '../helper/BufferToNumber'
import {UInt8ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * COTP — the ISO 8073 / ITU-T X.224 Connection-Oriented Transport Protocol TPDU, carried inside a TPKT
 * PDU (RFC 1006) and the transport layer of the IEC 61850 MMS / substation ISO stack. Each TPDU begins
 * with a Length Indicator (LI) — the number of header octets that FOLLOW the LI byte (it counts neither
 * the LI itself nor the user data) — then the PDU Type octet (its high nibble is the type code: 0xF0 = DT
 * Data, 0xE0 = CR Connect Request, 0xD0 = CC Connect Confirm, 0x80 = DR Disconnect Request, 0x50 = ER
 * Error, …), then type-specific header fields, then the user data (the ISO Session / Presentation / ACSE /
 * MMS bytes above).
 *
 * The single most common TPDU — DT (Data, 0xF0) — is structured: the octet after the PDU Type carries EOT
 * (bit 7, "end of TSDU") and the 7-bit TPDU-NR. Every OTHER TPDU type keeps its type-specific header
 * verbatim as `headerRest` hex (bounded by LI), so any TPDU round-trips byte-for-byte without fully
 * modelling each variant. `pduType` is stored as the FULL octet (e.g. DT = 0xF0 = 240), preserving the low
 * nibble (CDT credit on CR/CC, etc.) so nothing is lost. The user data is kept verbatim as `data` hex,
 * bounded by the parent TPKT's Length when present; sub-decoding the session/MMS layers above is deferred.
 * COTP is therefore effectively a leaf for now.
 */
export class COTP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (COTP.#schemaCache ??= COTP.#buildSchema())
    }

    /** DT (Data) is identified by the high nibble of the PDU Type octet being 0xF. */
    static #isDT(pduType: number): boolean {
        return (pduType & 0xf0) === 0xf0
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'COTP type=${pduType} li=${li}',
            properties: {
                //Length Indicator: the count of header octets following this byte (excludes LI + data).
                //Honoured when supplied; else derived from the PDU Type + any verbatim header bytes.
                li: {
                    type: 'integer',
                    label: 'Length Indicator',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: COTP): void {
                        this.instance.li.setValue(BufferToUInt8(this.readBytes(0, 1)))
                    },
                    encode: function (this: COTP): void {
                        const provided: number = this.instance.li.getValue(0)
                        let value: number = provided
                        if (!value) {
                            const dt: boolean = COTP.#isDT(this.instance.pduType.getValue(0))
                            const headerRest: Buffer = HexToBuffer(this.instance.headerRest.getValue(''))
                            //pduType(1) + (DT ? the EOT/TPDU-NR octet(1) : 0) + verbatim header bytes.
                            value = 1 + (dt ? 1 : 0) + headerRest.length
                        }
                        if (value > 255) {
                            this.recordError(this.instance.li.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        this.instance.li.setValue(value)
                        this.writeBytes(0, UInt8ToBuffer(value))
                    }
                },
                //Full PDU Type octet (high nibble = type code, low nibble kept verbatim), e.g. DT = 0xF0 = 240.
                pduType: this.fieldUInt('pduType', 1, 1, 'PDU Type'),
                //DT only: bit 7 of the octet at offset 2 — "end of TSDU". Meaningless for other types (left false).
                eot: {
                    type: 'boolean',
                    label: 'EOT',
                    decode: function (this: COTP): void {
                        const dt: boolean = COTP.#isDT(this.instance.pduType.getValue(0))
                        this.instance.eot.setValue(dt ? !!this.readBits(2, 1, 0, 1) : false)
                    },
                    encode: function (this: COTP): void {
                        const dt: boolean = COTP.#isDT(this.instance.pduType.getValue(0))
                        if (dt) this.writeBits(2, 1, 0, 1, this.instance.eot.getValue(false) ? 1 : 0)
                    }
                },
                //DT only: the low 7 bits of the octet at offset 2 — the TPDU sequence number.
                tpduNr: {
                    type: 'integer',
                    label: 'TPDU Number',
                    minimum: 0,
                    maximum: 127,
                    decode: function (this: COTP): void {
                        const dt: boolean = COTP.#isDT(this.instance.pduType.getValue(0))
                        this.instance.tpduNr.setValue(dt ? this.readBits(2, 1, 1, 7) : 0)
                    },
                    encode: function (this: COTP): void {
                        const dt: boolean = COTP.#isDT(this.instance.pduType.getValue(0))
                        if (dt) this.writeBits(2, 1, 1, 7, this.instance.tpduNr.getValue(0))
                    }
                },
                //The type-specific header bytes of a non-DT TPDU (CR/CC/DR/ER/…), bounded by LI and kept
                //verbatim so every TPDU variant round-trips byte-for-byte. Empty for a DT TPDU (its single
                //type-specific octet is structured into eot/tpduNr above).
                headerRest: {
                    type: 'string',
                    label: 'Header Rest',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: COTP): void {
                        const dt: boolean = COTP.#isDT(this.instance.pduType.getValue(0))
                        const li: number = this.instance.li.getValue(0)
                        const available: number = this.packet.length - this.startPos
                        //The COTP header occupies octets [0, 1 + li); clamp to the captured bytes.
                        let headerEnd: number = 1 + li
                        if (headerEnd > available) headerEnd = available
                        const restStart: number = dt ? 3 : 2
                        this.instance.headerRest.setValue(headerEnd > restStart ? BufferToHex(this.readBytes(restStart, headerEnd - restStart)) : '')
                    },
                    encode: function (this: COTP): void {
                        const dt: boolean = COTP.#isDT(this.instance.pduType.getValue(0))
                        const headerRest: string = this.instance.headerRest.getValue('')
                        if (headerRest) this.writeBytes(dt ? 3 : 2, HexToBuffer(headerRest))
                    }
                },
                //The user data (ISO Session / Presentation / ACSE / MMS bytes), kept verbatim. Bounded by
                //the parent TPKT's Length when available (so trailing bytes are not absorbed), else runs to
                //the end of the captured bytes.
                data: {
                    type: 'string',
                    label: 'Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: COTP): void {
                        const li: number = this.instance.li.getValue(0)
                        const available: number = this.packet.length - this.startPos
                        const dataStart: number = 1 + li
                        //Expose the user data as a dispatchable CHILD layer (RDP / S7comm / ISO-Session /
                        //MMS) instead of consuming it here, but ONLY when the upper PDU is fully self-
                        //contained in this packet: a DT TPDU with EOT set, riding on TPKT, whose TPKT-
                        //declared length exactly equals the captured remaining bytes. That rules out
                        //fragmentation (EOT=0, which a single-packet stateless codec cannot reassemble),
                        //truncation, and a pipelined trailing TPKT PDU (which an unbounded RawData child
                        //would otherwise swallow). In that case set data='' and return WITHOUT reading, so
                        //headerLength stops at the header end and the codec dispatches the remaining bytes.
                        const pduType: number = this.instance.pduType.getValue(0)
                        const dt: boolean = COTP.#isDT(pduType)
                        const eot: boolean = this.instance.eot.getValue(false)
                        //A DT with EOT set, or a Connection Request (0xE0) / Connection Confirm (0xD0)
                        //whose user data (an RDP Negotiation Request/Response) is single-PDU by nature.
                        const exposeChild: boolean = (dt && eot) || pduType === 0xe0 || pduType === 0xd0
                        if (exposeChild && this.prevCodecModule && this.prevCodecModule.id === 'tpkt') {
                            const cotpPdu: number = this.prevCodecModule.instance.length.getValue(0) - 4
                            if (cotpPdu === available && available > dataStart) {
                                this.instance.data.setValue('')
                                return
                            }
                        }
                        //Otherwise COTP remains a leaf and keeps the user data verbatim, bounded by the TPKT
                        //Length so a pipelined trailing PDU is left for a fresh TPKT dispatch.
                        let end: number = available
                        if (this.prevCodecModule && this.prevCodecModule.id === 'tpkt') {
                            const cotpPdu: number = this.prevCodecModule.instance.length.getValue(0) - 4
                            if (cotpPdu >= 0 && cotpPdu < end) end = cotpPdu
                        }
                        this.instance.data.setValue(end > dataStart ? BufferToHex(this.readBytes(dataStart, end - dataStart)) : '')
                    },
                    encode: function (this: COTP): void {
                        const li: number = this.instance.li.getValue(0)
                        const data: string = this.instance.data.getValue('')
                        if (data) this.writeBytes(1 + li, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 'cotp'

    public readonly name: string = 'COTP'

    public readonly nickname: string = 'COTP'

    //No demux keys: COTP is an unkeyed content-heuristic child that only rides on top of TPKT.
    public readonly matchKeys: string[] = []

    public match(): boolean {
        //COTP is carried exclusively inside a TPKT PDU — gate purely on the parent being TPKT so a stray
        //TCP payload is never mis-claimed (the heuristic chain offers COTP on every layer).
        return !!this.prevCodecModule && this.prevCodecModule.id === 'tpkt'
    }

    //Effectively a leaf for now — the session/MMS layers above are kept verbatim and decoded later.
    public readonly demuxProducers: DemuxProducer[] = []

}
