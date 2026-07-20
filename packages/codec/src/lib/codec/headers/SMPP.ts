import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToUInt32} from '../../helper/BufferToNumber'
import {UInt32ToBuffer} from '../../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Short Message Peer-to-Peer (SMPP 3.4), TCP port 2775 — the SMS-gateway ESME↔SMSC protocol. Every SMPP
 * PDU begins with a fixed 16-byte header (all big-endian): command_length (the total octet count of the
 * whole PDU, this header included), command_id (the operation, e.g. 0x00000001 bind_receiver,
 * 0x00000002 bind_transmitter, 0x00000004 submit_sm, 0x00000009 bind_transceiver, 0x80000009
 * bind_transceiver_resp — the 0x8000_0000 bit marks a response), command_status (0 = ESME_ROK on
 * requests, the error code on responses) and sequence_number (correlates a request with its response) —
 * followed by the command-specific body.
 *
 * The body layout is per-command (bind_*'s C-Octet-String system_id/password/system_type +
 * interface_version + address fields, submit_sm's addresses and short_message, plus optional TLVs) and
 * needs command-dependent parsing, so this single-PDU codec keeps the body verbatim as `body` hex
 * (byte-perfect) and does not sub-decode it. command_length is auto-computed from the body on encode when
 * not supplied, else honored verbatim (a crafted PDU may lie); the PDU is bounded by command_length so a
 * second pipelined PDU or trailing bytes are left to the codec's recursion / RawData. A well-formed PDU
 * round-trips byte-for-byte.
 *
 * command_id / command_status are decoded with unclamped uint32 fields (no hard enum) so any on-wire
 * operation or error value survives decode→encode without being rejected.
 */
export class SMPP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SMPP.#schemaCache ??= SMPP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SMPP cmd=${commandId} seq=${sequenceNumber}',
            properties: {
                commandLength: {
                    type: 'integer',
                    label: 'Command Length',
                    //minimum 0 (not 16): a crafted/corrupt PDU may carry a command_length below the 16-byte
                    //header, and that value must round-trip (honored verbatim) rather than being rejected by
                    //Ajv at the encode entry — decode never fails, encode is a faithful executor.
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: SMPP): void {
                        this.instance.commandLength.setValue(BufferToUInt32(this.readBytes(0, 4)))
                    },
                    encode: function (this: SMPP): void {
                        //command_length counts the whole PDU = 16-byte header + body. Honored when
                        //supplied (a crafted PDU may lie); else derived from the body.
                        const provided: number | undefined = this.instance.commandLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 16 + HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.commandLength.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.commandLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.commandLength.setValue(value)
                        this.writeBytes(0, UInt32ToBuffer(value))
                    }
                },
                //The operation code; the 0x80000000 bit marks a response. Kept as an unclamped uint32
                //(no hard enum) so any on-wire command_id round-trips.
                commandId: this.fieldUInt('commandId', 4, 4, 'Command ID'),
                //0 = ESME_ROK on requests; the operation's error code on responses. Unclamped uint32.
                commandStatus: this.fieldUInt('commandStatus', 8, 4, 'Command Status'),
                //Correlates a request PDU with its response PDU.
                sequenceNumber: this.fieldUInt('sequenceNumber', 12, 4, 'Sequence Number'),
                //The command-specific body after the 16-byte header, kept verbatim. Bounded by
                //command_length (the PDU ends at offset command_length) and the captured bytes, so
                //trailing / pipelined data is left to the codec's recursion / RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SMPP): void {
                        const remaining: number = this.packet.length - this.startPos
                        const length: number = this.instance.commandLength.getValue(0)
                        let end: number = length
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 16 ? BufferToHex(this.readBytes(16, end - 16)) : '')
                    },
                    encode: function (this: SMPP): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(16, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'smpp'

    public readonly name: string = 'Short Message Peer-to-Peer'

    public readonly nickname: string = 'SMPP'

    public readonly matchKeys: string[] = ['tcpport:2775']

    public match(): boolean {
        //SMPP rides on TCP port 2775. The 16-byte header carries no strong content magic, so the
        //well-known port is the signature: require the full header to be present. Selection stays
        //port-bucketed (matchKeys) like the other length-bounded TCP payload codecs.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        return this.packet.length - this.startPos >= 16
    }

    //A leaf header — the command-specific body requires per-command, TLV-aware parsing.
    public readonly demuxProducers: DemuxProducer[] = []

}
