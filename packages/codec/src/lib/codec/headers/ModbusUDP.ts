import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Modbus/UDP (MODBUS Application Protocol V1.1b3 + Modbus Messaging on TCP/IP V1.0b), UDP port 502. The
 * frame carries the same MBAP + PDU layout as Modbus/TCP but over UDP instead of a TCP stream: a 7-byte
 * MBAP header — Transaction Identifier, Protocol Identifier (0 for Modbus), Length, and Unit Identifier —
 * followed by the PDU (a Function Code and its data). The Length field counts the Unit Identifier plus the
 * PDU, so it bounds the message; a second pipelined PDU or trailing bytes are left to the codec's
 * recursion / RawData.
 *
 * Whether the PDU data is a request or a response is only knowable from the paired transaction, which is
 * cross-packet state — so this single-packet codec keeps the PDU data as raw hex (byte-perfect) and does
 * not sub-decode it. The Length is auto-computed from the data on encode when not supplied, else honored
 * verbatim (a crafted message may carry any Length). A well-formed message round-trips byte-for-byte.
 */
export class ModbusUDP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (ModbusUDP.#schemaCache ??= ModbusUDP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Modbus/UDP func=${functionCode} unit=${unitId}',
            properties: {
                transactionId: this.fieldUInt('transactionId', 0, 2, 'Transaction Identifier'),
                protocolId: this.fieldUInt('protocolId', 2, 2, 'Protocol Identifier'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: ModbusUDP): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(4, 2)))
                    },
                    encode: function (this: ModbusUDP): void {
                        //Length counts the Unit Identifier + PDU = 1 (unit) + 1 (function code) + data.
                        //Honored when supplied (a crafted message may lie); else derived from the data.
                        const provided: number | undefined = this.instance.length.getValue()
                        const value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 2 + HexToBuffer(this.instance.data.getValue('')).length
                        this.instance.length.setValue(value)
                        this.writeBytes(4, UInt16ToBuffer(value))
                    }
                },
                unitId: this.fieldUInt('unitId', 6, 1, 'Unit Identifier'),
                functionCode: this.fieldUInt('functionCode', 7, 1, 'Function Code'),
                //The PDU data after the function code, kept verbatim. Bounded by the MBAP Length (the
                //message ends at offset 6 + Length) and the captured bytes, so trailing/pipelined data
                //is not absorbed.
                data: {
                    type: 'string',
                    label: 'Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: ModbusUDP): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.length.getValue(0)
                        let end: number = 6 + length
                        if (end > remaining) end = remaining
                        this.instance.data.setValue(end > 8 ? BufferToHex(this.readBytes(8, end - 8)) : '')
                    },
                    encode: function (this: ModbusUDP): void {
                        const data: string = this.instance.data.getValue('')
                        if (data) this.writeBytes(8, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 'modbusudp'

    public readonly name: string = 'Modbus/UDP'

    public readonly nickname: string = 'Modbus'

    public readonly matchKeys: string[] = ['udpport:502']

    public match(): boolean {
        //Modbus/UDP rides on UDP port 502. Require the 7-byte MBAP header + a function code (8 bytes),
        //and a zero Protocol Identifier (the Modbus content signature) so non-Modbus 502 traffic falls
        //through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.packet.length - this.startPos < 8) return false
        return BufferToUInt16(this.readBytes(2, 2, true)) === 0
    }

    //A leaf header — the PDU data is kept as hex, not demuxed further.
    public readonly demuxProducers: DemuxProducer[] = []

}
