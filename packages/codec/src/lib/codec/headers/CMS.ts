import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'

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
                        this.instance.serviceData.setValue(end > 6 ? BufferToHex(this.readBytes(6, end - 6)) : '')
                    },
                    encode: function (this: CMS): void {
                        const data: string = this.instance.serviceData.getValue('')
                        if (data) this.writeBytes(6, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 'cms'

    public readonly name: string = 'CMS (China Substation Communication, DL/T 2811)'

    public readonly nickname: string = 'CMS'

    public readonly matchKeys: string[] = ['tcpport:8102']

    public match(): boolean {
        //CMS rides on TCP port 8102 (DL/T 2811 §6.6). Require the 4-byte APCH and the Protocol type
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
