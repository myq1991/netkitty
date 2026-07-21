import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {CodecModule} from '../types/CodecModule'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * S7comm — the Siemens S7 Communication protocol (S7-300/400/1200/1500 PLC), the application layer of
 * the S7 ISO-on-TCP stack: it rides inside a COTP DT (Data) TPDU, itself carried by a TPKT PDU on TCP
 * port 102 (RFC 1006). Every S7comm PDU begins with a fixed 10-byte header — a Protocol Id (always
 * 0x32), a ROSCTR (message class: 1 Job request, 2 Ack, 3 Ack_Data, 7 Userdata), a 2-byte Redundancy
 * Identification (reserved, normally 0), a 2-byte PDU Reference, and the 2-byte Parameter Length and
 * Data Length that delimit the two variable sections — plus, ONLY for the Ack / Ack_Data classes
 * (ROSCTR 2 or 3), a 2-byte error field (Error Class + Error Code). The Parameter section (the S7
 * function + its arguments) and the Data section (item values, results) then follow, sized by the two
 * length fields.
 *
 * The Parameter and Data sections are function-dependent, cross-PDU state (Setup Communication,
 * Read/Write Var, block up/download, PLC control, …), so this codec keeps them verbatim as bounded hex
 * (byte-perfect): `parameter` sized by Parameter Length and `data` sized by Data Length. The two length
 * fields are honor-else-derive (honored verbatim when supplied — a crafted PDU may lie — else derived
 * from the hex byte length of their section). Every field is BIG-ENDIAN (S7comm is not CIP/ENIP). A
 * well-formed PDU round-trips byte-for-byte.
 *
 * S7comm is gated purely on its parent being a COTP DT TPDU (prev.id === 'cotp') plus the Protocol Id
 * 0x32 signature at offset 0 (heuristicFallback), mirroring how COTP itself is an unkeyed
 * content-heuristic child of TPKT — nothing on TCP/102 other than a COTP-carried 0x32 PDU is S7comm.
 */
export class S7comm extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (S7comm.#schemaCache ??= S7comm.#buildSchema())
    }

    /** The 2-byte error field (Error Class + Error Code) is present ONLY on Ack (2) / Ack_Data (3). */
    static #hasError(rosctr: number): boolean {
        return rosctr === 2 || rosctr === 3
    }

    /** Length of the fixed header: 10 bytes, plus the 2-byte error field on Ack / Ack_Data. */
    static #headerLen(rosctr: number): number {
        return 10 + (S7comm.#hasError(rosctr) ? 2 : 0)
    }

    /**
     * Absolute byte offset (relative to this header) at which the COTP-delimited S7comm payload ends —
     * i.e. the end of the enclosing TPKT PDU. Used to double-cap the Parameter/Data sections so a lying
     * length field cannot read past the COTP payload into a trailing/pipelined TPKT PDU. Falls back to
     * the captured-bytes end when no bounding TPKT length is available.
     */
    #payloadEnd(): number {
        let end: number = this.packet.length - this.startPos
        for (const codecModule of this.prevCodecModules) {
            if (codecModule.id === 'tpkt') {
                //TPKT Length spans the whole TPKT PDU (its 4-byte header included); its absolute end is
                //the end of everything COTP carries, hence the end of this S7comm PDU.
                const tpktLength: number = codecModule.instance.length.getValue(0)
                const relEnd: number = codecModule.startPos + tpktLength - this.startPos
                if (relEnd >= 0 && relEnd < end) end = relEnd
            }
        }
        return end
    }

    /** honor-else-derive length field: honored verbatim when supplied, else derived from `sectionName`. */
    static #lengthField(name: string, offset: number, sectionName: string, label: string): any {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 65535,
            decode: function (this: S7comm): void {
                (this.instance as any)[name].setValue(BufferToUInt16(this.readBytes(offset, 2)))
            },
            encode: function (this: S7comm): void {
                const node: any = (this.instance as any)[name]
                const provided: number | undefined = node.getValue()
                let value: number = (provided !== undefined && provided !== null)
                    ? provided
                    : HexToBuffer((this.instance as any)[sectionName].getValue('')).length
                if (value > 65535) {
                    this.recordError(node.getPath(), 'Maximum value is 65535')
                    value = 65535
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(offset, UInt16ToBuffer(value))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'S7comm rosctr=${rosctr} ref=${pduReference}',
            properties: {
                //Protocol Id: always 0x32 for S7comm. A plain uint (no enum) so a crafted/off-spec value
                //still round-trips; the 0x32 signature gates selection in match(), not the schema.
                protocolId: this.fieldUInt('protocolId', 0, 1, 'Protocol Id'),
                //ROSCTR (message class): 1 Job, 2 Ack, 3 Ack_Data, 7 Userdata. Kept as a plain uint —
                //an unknown class must still decode and re-encode, so no enum constraint is applied.
                rosctr: this.fieldUInt('rosctr', 1, 1, 'ROSCTR'),
                //Redundancy Identification: reserved, normally 0x0000. Kept verbatim so any value round-trips.
                redundancyId: this.fieldHex('redundancyId', 2, 2, 'Redundancy Identification'),
                pduReference: this.fieldUInt('pduReference', 4, 2, 'PDU Reference'),
                //Parameter Length / Data Length delimit the two variable sections. honor-else-derive.
                parameterLength: this.#lengthField('parameterLength', 6, 'parameter', 'Parameter Length'),
                dataLength: this.#lengthField('dataLength', 8, 'data', 'Data Length'),
                //Error Class + Error Code: present ONLY on Ack (2) / Ack_Data (3) — bytes 10..11. For a
                //Job (1) / Userdata (7) PDU these octets do not exist, so decode leaves them 0 and encode
                //writes nothing (mirrors COTP's DT-only eot/tpduNr conditional fields).
                errorClass: {
                    type: 'integer',
                    label: 'Error Class',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: S7comm): void {
                        const rosctr: number = this.instance.rosctr.getValue(0)
                        this.instance.errorClass.setValue(S7comm.#hasError(rosctr) ? this.readBytes(10, 1)[0] : 0)
                    },
                    encode: function (this: S7comm): void {
                        const rosctr: number = this.instance.rosctr.getValue(0)
                        if (!S7comm.#hasError(rosctr)) return
                        let value: number = this.instance.errorClass.getValue(0)
                        if (value > 255) {
                            this.recordError(this.instance.errorClass.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) {
                            this.recordError(this.instance.errorClass.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.errorClass.setValue(value)
                        this.writeBytes(10, Buffer.from([value & 0xff]))
                    }
                },
                errorCode: {
                    type: 'integer',
                    label: 'Error Code',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: S7comm): void {
                        const rosctr: number = this.instance.rosctr.getValue(0)
                        this.instance.errorCode.setValue(S7comm.#hasError(rosctr) ? this.readBytes(11, 1)[0] : 0)
                    },
                    encode: function (this: S7comm): void {
                        const rosctr: number = this.instance.rosctr.getValue(0)
                        if (!S7comm.#hasError(rosctr)) return
                        let value: number = this.instance.errorCode.getValue(0)
                        if (value > 255) {
                            this.recordError(this.instance.errorCode.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) {
                            this.recordError(this.instance.errorCode.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.errorCode.setValue(value)
                        this.writeBytes(11, Buffer.from([value & 0xff]))
                    }
                },
                //Parameter section (S7 function + arguments), kept verbatim. Sized by Parameter Length,
                //double-capped by the COTP-delimited payload end so a lying length cannot swallow the
                //Data section or a trailing TPKT PDU.
                parameter: {
                    type: 'string',
                    label: 'Parameter',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: S7comm): void {
                        const rosctr: number = this.instance.rosctr.getValue(0)
                        const headerLen: number = S7comm.#headerLen(rosctr)
                        const parameterLength: number = this.instance.parameterLength.getValue(0)
                        let end: number = headerLen + parameterLength
                        const payloadEnd: number = this.#payloadEnd()
                        if (end > payloadEnd) end = payloadEnd
                        this.instance.parameter.setValue(end > headerLen ? BufferToHex(this.readBytes(headerLen, end - headerLen)) : '')
                    },
                    encode: function (this: S7comm): void {
                        const rosctr: number = this.instance.rosctr.getValue(0)
                        const headerLen: number = S7comm.#headerLen(rosctr)
                        const parameter: string = this.instance.parameter.getValue('')
                        if (parameter) this.writeBytes(headerLen, HexToBuffer(parameter))
                    }
                },
                //Data section (item values / results), kept verbatim. Sized by Data Length, double-capped
                //by the COTP-delimited payload end (so trailing/pipelined bytes fall through to the codec).
                data: {
                    type: 'string',
                    label: 'Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: S7comm): void {
                        const rosctr: number = this.instance.rosctr.getValue(0)
                        const headerLen: number = S7comm.#headerLen(rosctr)
                        const parameterLength: number = this.instance.parameterLength.getValue(0)
                        const dataLength: number = this.instance.dataLength.getValue(0)
                        const dataStart: number = headerLen + parameterLength
                        let end: number = dataStart + dataLength
                        const payloadEnd: number = this.#payloadEnd()
                        if (end > payloadEnd) end = payloadEnd
                        this.instance.data.setValue(end > dataStart ? BufferToHex(this.readBytes(dataStart, end - dataStart)) : '')
                    },
                    encode: function (this: S7comm): void {
                        const rosctr: number = this.instance.rosctr.getValue(0)
                        const headerLen: number = S7comm.#headerLen(rosctr)
                        const parameterLength: number = this.instance.parameterLength.getValue(0)
                        const data: string = this.instance.data.getValue('')
                        if (data) this.writeBytes(headerLen + parameterLength, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 's7comm'

    public readonly name: string = 'S7 Communication'

    public readonly nickname: string = 'S7comm'

    //S7comm rides on TCP port 102, but always inside a COTP DT TPDU. Like COTP (which demuxes off TPKT
    //with no matchKeys), selection is by content: heuristicFallback lists it in the heuristic chain and
    //match() gates on the COTP parent plus the 0x32 signature.
    public readonly matchKeys: string[] = []

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        //S7comm is carried exclusively inside a COTP DT TPDU — gate on the parent being COTP so a stray
        //TCP/102 payload is never mis-claimed, then confirm the Protocol Id 0x32 signature at offset 0.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'cotp') return false
        if (this.packet.length - this.startPos < 1) return false
        return this.readBytes(0, 1, true)[0] === 0x32
    }

    //A leaf for now — the Parameter/Data sections require per-function, cross-PDU parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
