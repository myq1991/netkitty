import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {PerDecoder, AsnType} from './cms/PerDecoder'
import {SERVICE_PDU, SERVICE_NAMES, ServicePdu} from './cms/AcsiPdu'

/**
 * CMS — China smart-substation communication (DL/T 2811-2024, "变电站二次系统通信报文规范"), the
 * State-Grid replacement for IEC 61850 MMS that maps ACSI directly onto TCP (port 8102), dropping the
 * OSI upper layers. Per DL/T 2811 §6.1, an Application Protocol Data Unit (APDU) is an Application
 * Protocol Control Header (APCH) followed by an Application Service Data Unit (ASDU):
 *
 *   APCH (4 bytes): Control Code CC — Next(bit8) + Resp(bit7) + Err(bit6) + bak(bit5) + a 4-bit Protocol
 *                   type PI (low nibble, = 0x01); Service Code SC (1 byte, §6.1.2 Table 1: 1 Associate,
 *                   2 Abort, 3 Release, 48 GetDataValues, 83 GetAllDataValues, 154 AssociateNegotiate,
 *                   155 GetAllDataDefinition, …); Frame Length FL (2 bytes, little-endian, the APDU
 *                   length excluding the APCH).
 *   ASDU (FL bytes): Service Request Id ReqID (2 bytes, little-endian, §6.2 — 1..65535, 0 for Report)
 *                    + the service data area (encoded per the SC, kept verbatim here).
 *
 * An empty frame (§6.3) has FL=0 (APCH only) or FL=2 (APCH+ReqID). A large ASDU is framed (§6.5) with
 * the Next bit set. A CMS PDU can also exceed one TCP segment; this single-packet stateless codec
 * structures the APCH + the ASDU bytes present in the packet, leaving TCP-stream reassembly to a higher
 * layer (mid-PDU continuation segments carry no APCH — their first byte's low nibble is not the PI 0x01
 * — so they fall to raw). A single frame round-trips byte-for-byte.
 */
export class CMS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (CMS.#schemaCache ??= CMS.#buildSchema())
    }

    static #bit(name: string, bitOffset: number, label: string): any {
        return {
            type: 'boolean', label: label,
            decode: function (this: CMS): void {
                (this.instance as any)[name].setValue(!!this.readBits(0, 1, bitOffset, 1))
            },
            encode: function (this: CMS): void {
                this.writeBits(0, 1, bitOffset, 1, (this.instance as any)[name].getValue(false) ? 1 : 0)
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'CMS SC=${serviceCode} ReqID=${reqId}',
            properties: {
                //==== APCH — Control Code CC (byte 1) ====
                //Next: more frames follow (application-level framing of a large ASDU, §6.5).
                next: this.#bit('next', 0, 'Next'),
                //Resp: this APDU is a response (vs a request).
                resp: this.#bit('resp', 1, 'Resp'),
                //Err: an error response.
                err: this.#bit('err', 2, 'Err'),
                //bak: reserved.
                bak: this.#bit('bak', 3, 'bak'),
                //Protocol type PI — the low nibble, 0x01 for DL/T 2811.
                protocolType: {
                    type: 'integer', label: 'Protocol Type', minimum: 0, maximum: 15,
                    decode: function (this: CMS): void {
                        this.instance.protocolType.setValue(this.readBits(0, 1, 4, 4))
                    },
                    encode: function (this: CMS): void {
                        this.writeBits(0, 1, 4, 4, this.instance.protocolType.getValue(1) & 0x0f)
                    }
                },
                //Service Code SC (byte 2) — the service in the data area (Table 1).
                serviceCode: this.fieldUInt('serviceCode', 1, 1, 'Service Code'),
                //Frame Length FL (bytes 3-4, LITTLE-ENDIAN) — the APDU length excluding the 4-byte APCH,
                //i.e. the ASDU length. Honored verbatim.
                frameLength: {
                    type: 'integer', label: 'Frame Length', minimum: 0, maximum: 65535,
                    decode: function (this: CMS): void {
                        const b: Buffer = this.readBytes(2, 2)
                        this.instance.frameLength.setValue((b[0] | (b[1] << 8)) & 0xffff)
                    },
                    encode: function (this: CMS): void {
                        let value: number = this.instance.frameLength.getValue(0)
                        if (value > 65535) value = 65535
                        if (value < 0) value = 0
                        this.writeBytes(2, Buffer.from([value & 0xff, (value >> 8) & 0xff]))
                    }
                },
                //==== ASDU ====
                //Service Request Id ReqID (bytes 5-6, LITTLE-ENDIAN). Present only when the ASDU carries it
                //(FL >= 2); an FL=0 empty frame (§6.3) has no ASDU at all.
                reqId: {
                    type: 'integer', label: 'Request Id', minimum: 0, maximum: 65535,
                    decode: function (this: CMS): void {
                        const available: number = this.packet.length - this.startPos
                        if (this.instance.frameLength.getValue(0) < 2 || available < 6) return
                        const b: Buffer = this.readBytes(4, 2)
                        this.instance.reqId.setValue((b[0] | (b[1] << 8)) & 0xffff)
                    },
                    encode: function (this: CMS): void {
                        const reqId: number | undefined = this.instance.reqId.getValue()
                        if (reqId === undefined || reqId === null) return
                        this.writeBytes(4, Buffer.from([reqId & 0xff, (reqId >> 8) & 0xff]))
                    }
                },
                //The service data area (encoded per the Service Code), kept verbatim. Bounded by FL (minus
                //the 2-byte ReqID) and the captured bytes — for a PDU split across TCP segments only the
                //bytes present in this packet are captured; the rest is left to a higher reassembly layer.
                serviceData: {
                    type: 'string', label: 'Service Data', contentEncoding: 'hex',
                    decode: function (this: CMS): void {
                        const available: number = this.packet.length - this.startPos
                        const fl: number = this.instance.frameLength.getValue(0)
                        if (fl < 2) return
                        let end: number = 4 + fl
                        if (end > available) end = available
                        //Service data begins after the 2-byte ReqID (offset 6).
                        if (end <= 6) return
                        const buf: Buffer = this.readBytes(6, end - 6)
                        this.instance.serviceData.setValue(BufferToHex(buf))
                        //Display-only: structure the service data area per the Service Code (§6.10, PER).
                        const decoded: object | undefined = CMS.#decodeServiceData(
                            this.instance.serviceCode.getValue(0),
                            !!this.instance.resp.getValue(false),
                            !!this.instance.err.getValue(false),
                            buf
                        )
                        if (decoded !== undefined) {
                            this.instance.serviceDataDecoded.setValue(decoded)
                        } else {
                            //No transcribed structure (e.g. a data/definition response, whose GB/T 33603
                            //"M-coding" body framing is not fully specified in the available standards).
                            //Best-effort: surface the readable IEC 61850 identifiers (object/attribute names,
                            //CDC types, string values) as display metadata — not a structural decode.
                            const strings: string[] = CMS.#extractStrings(buf)
                            if (strings.length) this.instance.serviceDataStrings.setValue(strings)
                        }
                    },
                    encode: function (this: CMS): void {
                        const data: string = this.instance.serviceData.getValue('')
                        if (data) this.writeBytes(6, HexToBuffer(data))
                    }
                },
                //Display-only structured view of the service data area, decoded with ALIGNED BASIC-PER
                //(DL/T 2811 §6.10) per the Service Code. Populated on decode by the serviceData closure
                //above; it has no encode closure, so `serviceData` (hex) stays the authoritative encode
                //form and the structured view can never perturb the re-emitted bytes.
                serviceDataDecoded: {type: 'object', label: 'Service Data (decoded)'},
                //Display-only best-effort readable identifiers extracted from a service data area that has
                //no transcribed structure (the GB/T 33603 M-coded responses). No encode closure.
                serviceDataStrings: {type: 'array', label: 'Readable Identifiers', items: {type: 'string'}}
            }
        }
    }

    /**
     * Best-effort ALIGNED BASIC-PER decode of the service data area for display. Returns a plain tree
     * {service, direction, …fields} when the Service Code + direction has a transcribed ASN.1 descriptor,
     * `incomplete: true` if the decoder bailed partway, or undefined when nothing is structured (leaving
     * the verbatim hex as the only view). Never throws.
     */
    /**
     * Best-effort readable-identifier extraction from an M-coded (GB/T 33603) service data area whose exact
     * framing is not fully specified in the available standards. IEC 61850 names/values are length-prefixed
     * in the low 7 bits of a leading octet; this collects each run of `len` identifier characters
     * ([A-Za-z0-9_/]) that starts with a letter — the object/attribute names, CDC types and string values
     * (Mod, stVal, INC, vendor, …). Bounded and never-throwing. This is display metadata, not a structural
     * decode: it makes no claim about the record structure and never affects the re-emitted bytes.
     */
    static #extractStrings(buf: Buffer): string[] {
        const isId = (b: number): boolean =>
            (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || b === 0x5f || b === 0x2f
        const isAlpha = (b: number): boolean => (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a)
        const out: string[] = []
        for (let i: number = 0; i + 1 < buf.length && out.length < 256; i++) {
            const len: number = buf[i] & 0x7f
            if (len < 2 || i + 1 + len > buf.length) continue
            if (!isAlpha(buf[i + 1])) continue
            let ok: boolean = true
            for (let j: number = 1; j < len; j++) if (!isId(buf[i + 1 + j])) { ok = false; break }
            if (ok) {
                out.push(buf.subarray(i + 1, i + 1 + len).toString('latin1'))
                i += len
            }
        }
        return out
    }

    static #decodeServiceData(serviceCode: number, isResponse: boolean, isError: boolean, buf: Buffer): object | undefined {
        const entry: ServicePdu | undefined = SERVICE_PDU[serviceCode]
        if (!entry) return undefined
        //Error responses carry a ServiceError, not the normal response PDU — not structured in this slice.
        const type: AsnType | undefined = isError ? undefined : (isResponse ? entry.response : entry.request)
        if (!type) return undefined
        try {
            const decoder: PerDecoder = new PerDecoder(buf)
            const tree: unknown = decoder.decode(type)
            const head: object = {
                service: SERVICE_NAMES[serviceCode] ?? String(serviceCode),
                direction: isResponse ? 'response' : 'request'
            }
            const body: object = (tree !== null && typeof tree === 'object') ? tree as object : {}
            return decoder.bailed ? {...head, ...body, incomplete: true} : {...head, ...body}
        } catch {
            return undefined
        }
    }

    public readonly id: string = 'cms'

    public readonly name: string = 'CMS (China Substation Communication, DL/T 2811)'

    public readonly nickname: string = 'CMS'

    public readonly matchKeys: string[] = ['tcpport:8102', 'tcpport:9102']

    public match(): boolean {
        //CMS rides on TCP port 8102 (DL/T 2811 §6.6); some deployments also expose it on 9102 (the 国密
        //TLCP port), where it can appear in the clear. Require the 4-byte APCH and the Protocol type
        //PI = 0x01 in the low nibble of the Control Code, so non-CMS traffic and mid-PDU TCP-continuation
        //segments (which begin with ASDU data bytes, not an APCH) fall through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 4) return false
        return (this.readBytes(0, 1, true)[0] & 0x0f) === 0x01
    }

    //A leaf for this slice — the service data area is kept verbatim (its per-service ACSI encoding, DL/T
    //2811 §6.10 / §7, is a later slice).
    public readonly demuxProducers: DemuxProducer[] = []

}
