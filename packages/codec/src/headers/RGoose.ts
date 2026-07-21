import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt8, BufferToUInt16, BufferToUInt32} from '../helper/BufferToNumber'
import {UInt16ToBuffer, UInt32ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * One payload item inside the Session User Information (a GOOSE/SV/Tunnel APDU with its 6-byte header).
 */
type RGoosePayloadItem = {payloadType: number, simulation: number, appid: number, apduLength: number, apdu: string}

/**
 * IEC 61850-90-5 Session protocol — Routable GOOSE / Routable SV (R-GOOSE / R-SV).
 *
 * Carries a GOOSE (goosePdu) or SV (savPdu) APDU over UDP inside an OSI-style Session PDU (SPDU). One
 * header handles both, branching on the Session Identifier (SI) byte: 0xA1 = non-tunnelled GOOSE,
 * 0xA2 = non-tunnelled SV, 0xA0 = tunnelled. This is a leaf (Slice 1): each payload item's APDU is kept
 * as bounded raw hex — structuring it via the shared BER/GOOSE/SV decoders is deferred to Slice 2, so we
 * deliberately do NOT recurse into Goose.ts / IEC61850SampledValues.ts (that would swallow the trailing
 * signature and any 2nd payload item). All multi-byte session fields are big-endian.
 *
 * ── VERIFIED BYTE LAYOUT (cross-checked against Wireshark 4.6.7 packet-goose.c `dissect_rgoose`, and
 *    tshark's own R-GOOSE dissection of a crafted frame; offsets are header-relative) ──────────────────
 *   off  w   field                         source
 *    0   1   SI (Session Identifier)        packet-goose.c OSI_SPDU_* (0xA0 tunneled, 0xA1 GOOSE, 0xA2 SV, 0xA3 mgmt)
 *    1   1   LI (session header length)     hf_goose_session_hdr_length (display only; proto_item_set_len=LI+2)
 *    2   1   Common session header id       hf_goose_content_id (0x80)
 *    3   1   Header length                  hf_goose_hdr_length
 *    4   4   SPDU length                    hf_goose_spdu_lenth  (BE)
 *    8   4   SPDU number                    hf_goose_spdu_num    (BE)
 *   12   2   Version                        hf_goose_version     (BE, =1)
 *   ── Security information subtree ──
 *   14   4   Time of current key            hf_goose_current_key_t (BE)
 *   18   2   Time to next key               hf_goose_next_key_t    (BE)
 *   20   4   Key ID                         hf_goose_key_id        (BE)
 *   24   1   Initialization vector length   hf_goose_init_vec_length  → ivLen
 *   25  iv   Initialization vector          hf_goose_init_vec (present only if ivLen>0)
 *   ── Session user information ──
 *   25+iv  4 Payload length                 hf_goose_payload_length (BE); bounds the payload-item walk
 *   ── per payload item (APDU_HEADER_SIZE=6, then the APDU) ──
 *   +0   1   Payload type tag               hf_goose_apdu_tag (0x81 GOOSE, 0x82 SV, 0x83 tunnel, 0x84 mgmt)
 *   +1   1   Simulation flag                hf_goose_apdu_simulation
 *   +2   2   APPID                          hf_goose_apdu_appid  (BE)
 *   +4   2   APDU length                    hf_goose_apdu_length (BE)
 *   +6   N   APDU (goosePdu 0x61.. / savPdu 0x60.. BER)
 *   ── trailer (after payload length consumed) ──
 *        v   Signature / HMAC               optional 0xAF-tagged padding then HMAC; Wireshark lumps the
 *                                           trailing bytes as hf_goose_hmac (it does not parse a 0x85 tag)
 *
 * NOTE (layout uncertainty, resolved in favour of tshark): some 90-5 texts describe the security area as
 * TimeOfCurrentKey(4)+TimeToNextKey(2)+SecurityAlgorithm(enc 1 + MAC 1)+KeyID(4). Wireshark 4.6.7 instead
 * models those bytes as KeyID(4)+InitVectorLength(1)+InitVector — the SAME octets, different field names.
 * tshark is the byte-layout gate here, so we follow Wireshark's interpretation exactly.
 *
 * There is NO explicit payload-item count: items are walked accumulating (6 + APDU length) until the
 * Payload length is consumed (matches Wireshark's `while (apdu_offset < payload_length)` loop).
 *
 * TRANSPORT: real R-GOOSE reaches Wireshark's dissector via a CLTP (ISO 8602) UD TPDU heuristic over UDP,
 * but the common/libiec61850 wire form puts the SPDU directly in the UDP payload (SI as the first byte);
 * that is the form modelled here (matchKeys udpport:102, SI-signature match), and the form the fixture
 * ships. The session byte layout itself was validated by wrapping this SPDU in a minimal CLTP UD TPDU and
 * confirming tshark dissects it as R-GOOSE with the expected SPDU number / APPID / goosePdu / HMAC.
 *
 * Length fields (LI / Header length / SPDU length / Payload length / per-item APDU length) are honored
 * when present and derived only when absent — a well-formed frame's derived values equal the decoded
 * ones, so it round-trips byte-for-byte. A crafted frame that lies is re-emitted faithfully as long as
 * its payload is honestly tiled by items (the signature boundary is taken from the actual item bytes on
 * both decode and encode); a self-contradictory payloadLength that overshoots the item span by a partial
 * item is best-effort, like a truncated frame.
 */
export class RGoose extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (RGoose.#schemaCache ??= RGoose.#buildSchema())
    }

    /** The SPDU bytes available in this UDP datagram (so a retained trailer/padding is not over-read). */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /** Initialization-vector length (drives every offset after the fixed 25-byte session header). */
    #ivLen(): number {
        const value: number = this.instance.security.initVecLength.getValue(0)
        const n: number = typeof value === 'number' ? value : parseInt(String(value))
        return Number.isFinite(n) && n > 0 ? n : 0
    }

    /** Offset of the Payload length field: fixed 25-byte header + the variable IV. */
    #payloadLengthOffset(): number {
        return 25 + this.#ivLen()
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'R-GOOSE/R-SV spdu=${spduNumber} si=${si}',
            properties: {
                si: this.fieldUInt('si', 0, 1, 'Session Identifier'),
                li: {
                    type: 'integer', label: 'Session Header Length', minimum: 0, maximum: 255,
                    decode: function (this: RGoose): void { this.instance.li.setValue(BufferToUInt8(this.readBytes(1, 1))) },
                    encode: function (this: RGoose): void {
                        const value: number | undefined = this.instance.li.getValue()
                        //Honor when present, else derive: octets from the common header id (offset 2) to the
                        //end of the security info (= where the payload length begins, minus those 2 bytes).
                        const li: number = (value === undefined || value === null) ? this.#payloadLengthOffset() - 2 : value
                        this.instance.li.setValue(li)
                        this.writeBytes(1, Buffer.from([li & 0xff]))
                    }
                },
                commonHeaderId: {
                    type: 'integer', label: 'Common Session Header Id', minimum: 0, maximum: 255,
                    decode: function (this: RGoose): void { this.instance.commonHeaderId.setValue(BufferToUInt8(this.readBytes(2, 1))) },
                    encode: function (this: RGoose): void {
                        const value: number | undefined = this.instance.commonHeaderId.getValue()
                        const id: number = (value === undefined || value === null) ? 0x80 : value
                        this.instance.commonHeaderId.setValue(id)
                        this.writeBytes(2, Buffer.from([id & 0xff]))
                    }
                },
                headerLength: {
                    type: 'integer', label: 'Header Length', minimum: 0, maximum: 255,
                    decode: function (this: RGoose): void { this.instance.headerLength.setValue(BufferToUInt8(this.readBytes(3, 1))) },
                    encode: function (this: RGoose): void {
                        const value: number | undefined = this.instance.headerLength.getValue()
                        //Honor when present, else derive: octets from the SPDU length field (offset 4) to the
                        //end of the security info.
                        const hl: number = (value === undefined || value === null) ? this.#payloadLengthOffset() - 4 : value
                        this.instance.headerLength.setValue(hl)
                        this.writeBytes(3, Buffer.from([hl & 0xff]))
                    }
                },
                spduLength: {
                    type: 'integer', label: 'SPDU Length', minimum: 0, maximum: 4294967295,
                    decode: function (this: RGoose): void { this.instance.spduLength.setValue(BufferToUInt32(this.readBytes(4, 4))) },
                    encode: function (this: RGoose): void {
                        const value: number | undefined = this.instance.spduLength.getValue()
                        if (value !== undefined && value !== null) {
                            this.instance.spduLength.setValue(value)
                            this.writeBytes(4, UInt32ToBuffer(value))
                            return
                        }
                        //Derive: octets from the SPDU number field (offset 8) to the end of the SPDU
                        //(payload + signature). Computed once the whole header has been written.
                        this.writeBytes(4, UInt32ToBuffer(0))
                        this.addPostSelfEncodeHandler((): void => {
                            const derived: number = this.length - 8 < 0 ? 0 : this.length - 8
                            this.instance.spduLength.setValue(derived)
                            this.writeBytes(4, UInt32ToBuffer(derived))
                        })
                    }
                },
                spduNumber: this.fieldUInt('spduNumber', 8, 4, 'SPDU Number'),
                version: {
                    type: 'integer', label: 'Version', minimum: 0, maximum: 65535,
                    decode: function (this: RGoose): void { this.instance.version.setValue(BufferToUInt16(this.readBytes(12, 2))) },
                    encode: function (this: RGoose): void {
                        const value: number | undefined = this.instance.version.getValue()
                        const version: number = (value === undefined || value === null) ? 1 : value
                        this.instance.version.setValue(version)
                        this.writeBytes(12, UInt16ToBuffer(version))
                    }
                },
                security: {
                    type: 'object',
                    label: 'Security Information',
                    properties: {
                        timeCurrentKey: {
                            type: 'integer', label: 'Time of Current Key', minimum: 0, maximum: 4294967295,
                            decode: function (this: RGoose): void { this.instance.security.timeCurrentKey.setValue(BufferToUInt32(this.readBytes(14, 4))) },
                            encode: function (this: RGoose): void { this.writeBytes(14, UInt32ToBuffer(this.instance.security.timeCurrentKey.getValue(0))) }
                        },
                        timeNextKey: {
                            type: 'integer', label: 'Time to Next Key', minimum: 0, maximum: 65535,
                            decode: function (this: RGoose): void { this.instance.security.timeNextKey.setValue(BufferToUInt16(this.readBytes(18, 2))) },
                            encode: function (this: RGoose): void { this.writeBytes(18, UInt16ToBuffer(this.instance.security.timeNextKey.getValue(0))) }
                        },
                        keyId: {
                            type: 'integer', label: 'Key ID', minimum: 0, maximum: 4294967295,
                            decode: function (this: RGoose): void { this.instance.security.keyId.setValue(BufferToUInt32(this.readBytes(20, 4))) },
                            encode: function (this: RGoose): void { this.writeBytes(20, UInt32ToBuffer(this.instance.security.keyId.getValue(0))) }
                        },
                        initVecLength: {
                            type: 'integer', label: 'Init Vector Length', minimum: 0, maximum: 255,
                            decode: function (this: RGoose): void { this.instance.security.initVecLength.setValue(BufferToUInt8(this.readBytes(24, 1))) },
                            encode: function (this: RGoose): void {
                                const value: number | undefined = this.instance.security.initVecLength.getValue()
                                //Honor when present, else derive from the init-vector hex length.
                                const iv: Buffer = HexToBuffer(this.instance.security.initVec.getValue(''))
                                const len: number = (value === undefined || value === null) ? iv.length : value
                                this.instance.security.initVecLength.setValue(len)
                                this.writeBytes(24, Buffer.from([len & 0xff]))
                            }
                        },
                        initVec: {
                            type: 'string', label: 'Init Vector', contentEncoding: StringContentEncodingEnum.HEX,
                            decode: function (this: RGoose): void {
                                const ivLen: number = this.#ivLen()
                                this.instance.security.initVec.setValue(ivLen > 0 ? BufferToHex(this.readBytes(25, ivLen)) : '')
                            },
                            encode: function (this: RGoose): void {
                                const iv: Buffer = HexToBuffer(this.instance.security.initVec.getValue(''))
                                if (iv.length) this.writeBytes(25, iv)
                            }
                        }
                    }
                },
                payloadLength: {
                    type: 'integer', label: 'Payload Length', minimum: 0, maximum: 4294967295,
                    decode: function (this: RGoose): void {
                        this.instance.payloadLength.setValue(BufferToUInt32(this.readBytes(this.#payloadLengthOffset(), 4)))
                    },
                    encode: function (this: RGoose): void {
                        const value: number | undefined = this.instance.payloadLength.getValue()
                        let length: number
                        if (value !== undefined && value !== null) {
                            length = value
                        } else {
                            //Derive: sum of (6-byte APDU header + APDU bytes) over every payload item —
                            //exactly the span Wireshark walks against the payload length.
                            const items: RGoosePayloadItem[] = this.instance.payloadItems.getValue([])
                            length = (Array.isArray(items) ? items : []).reduce((sum: number, item: RGoosePayloadItem): number =>
                                sum + 6 + HexToBuffer(item && item.apdu ? item.apdu : '').length, 0)
                        }
                        this.instance.payloadLength.setValue(length)
                        this.writeBytes(this.#payloadLengthOffset(), UInt32ToBuffer(length))
                    }
                },
                payloadItems: {
                    type: 'array',
                    label: 'Payload Items',
                    items: {
                        type: 'object',
                        properties: {
                            payloadType: {type: 'integer', label: 'Payload Type', minimum: 0, maximum: 255},
                            simulation: {type: 'integer', label: 'Simulation', minimum: 0, maximum: 255},
                            appid: {type: 'integer', label: 'APPID', minimum: 0, maximum: 65535},
                            apduLength: {type: 'integer', label: 'APDU Length', minimum: 0, maximum: 65535},
                            apdu: {type: 'string', label: 'APDU', contentEncoding: StringContentEncodingEnum.HEX}
                        }
                    },
                    decode: function (this: RGoose): void {
                        const available: number = this.#available()
                        const start: number = this.#payloadLengthOffset() + 4
                        const payloadLength: number = this.instance.payloadLength.getValue(0)
                        //The payload length bounds the item walk; clamp to the datagram so a lying length
                        //cannot read past the buffer.
                        const end: number = Math.min(start + payloadLength, available)
                        const items: RGoosePayloadItem[] = []
                        let offset: number = start
                        let guard: number = 0
                        while (offset + 6 <= end && guard++ < 4096) {
                            const payloadType: number = BufferToUInt8(this.readBytes(offset, 1))
                            const simulation: number = BufferToUInt8(this.readBytes(offset + 1, 1))
                            const appid: number = BufferToUInt16(this.readBytes(offset + 2, 2))
                            const apduLength: number = BufferToUInt16(this.readBytes(offset + 4, 2))
                            const apduAvail: number = Math.min(apduLength, end - (offset + 6))
                            const apdu: string = apduAvail > 0 ? BufferToHex(this.readBytes(offset + 6, apduAvail)) : ''
                            items.push({payloadType: payloadType, simulation: simulation, appid: appid, apduLength: apduLength, apdu: apdu})
                            offset += 6 + apduLength
                        }
                        this.instance.payloadItems.setValue(items)
                    },
                    encode: function (this: RGoose): void {
                        const items: RGoosePayloadItem[] = this.instance.payloadItems.getValue([])
                        let offset: number = this.#payloadLengthOffset() + 4
                        ;(Array.isArray(items) ? items : []).forEach((item: RGoosePayloadItem): void => {
                            const apdu: Buffer = HexToBuffer(item && item.apdu ? item.apdu : '')
                            //Honor the item's APDU length when supplied, else derive from the APDU bytes.
                            const apduLength: number = (item && item.apduLength !== undefined && item.apduLength !== null) ? item.apduLength : apdu.length
                            this.writeBytes(offset, Buffer.from([(item && item.payloadType ? item.payloadType : 0) & 0xff]))
                            this.writeBytes(offset + 1, Buffer.from([(item && item.simulation ? item.simulation : 0) & 0xff]))
                            this.writeBytes(offset + 2, UInt16ToBuffer(item && item.appid ? item.appid : 0))
                            this.writeBytes(offset + 4, UInt16ToBuffer(apduLength))
                            if (apdu.length) this.writeBytes(offset + 6, apdu)
                            //Advance by the actual bytes written so items stay contiguous.
                            offset += 6 + apdu.length
                        })
                    }
                },
                signature: {
                    type: 'string',
                    label: 'Signature',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: RGoose): void {
                        const available: number = this.#available()
                        //Everything after the decoded payload items is the signature / HMAC trailer (possibly
                        //0xAF-tagged padding + HMAC), kept verbatim. The start is computed from the ACTUAL
                        //decoded item bytes — identical to the encode side below — rather than from the
                        //payloadLength field, so decode and encode are symmetric by construction: no byte is
                        //dropped even if a crafted payloadLength overshoots the real item span by a partial
                        //item (a payloadLength honestly tiled by items gives the same offset either way).
                        const items: RGoosePayloadItem[] = this.instance.payloadItems.getValue([])
                        let sigStart: number = this.#payloadLengthOffset() + 4
                        ;(Array.isArray(items) ? items : []).forEach((item: RGoosePayloadItem): void => {
                            sigStart += 6 + HexToBuffer(item && item.apdu ? item.apdu : '').length
                        })
                        this.instance.signature.setValue(sigStart < available ? BufferToHex(this.readBytes(sigStart, available - sigStart)) : '')
                    },
                    encode: function (this: RGoose): void {
                        const signature: Buffer = HexToBuffer(this.instance.signature.getValue(''))
                        if (!signature.length) return
                        const items: RGoosePayloadItem[] = this.instance.payloadItems.getValue([])
                        let sigStart: number = this.#payloadLengthOffset() + 4
                        ;(Array.isArray(items) ? items : []).forEach((item: RGoosePayloadItem): void => {
                            sigStart += 6 + HexToBuffer(item && item.apdu ? item.apdu : '').length
                        })
                        this.writeBytes(sigStart, signature)
                    }
                }
            }
        }
    }

    public readonly id: string = 'r-session'

    public readonly name: string = 'IEC 61850-90-5 Session'

    public readonly nickname: string = 'R-GOOSE/R-SV'

    public readonly matchKeys: string[] = ['udpport:102']

    public match(): boolean {
        //A UDP child. Require the minimum session header (Wireshark's heuristic floor is 27 bytes) and a
        //Session Identifier in the R-GOOSE/R-SV/tunnel set. No heuristicFallback: recognized only on the
        //well-known UDP port 102, gated by the SI signature.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.#available() < 27) return false
        const si: number = this.readBytes(0, 1, true)[0]
        return si === 0xA0 || si === 0xA1 || si === 0xA2
    }

    //A leaf for Slice 1: each payload item's APDU is retained as bounded raw hex rather than recursing
    //into the GOOSE/SV decoders (structuring the APDU is Slice 2).
    public readonly demuxProducers: DemuxProducer[] = []

}
