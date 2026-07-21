import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * GE-SRTP — GE Fanuc (GE Intelligent Platforms) Service Request Transport Protocol, TCP port 18245.
 * The proprietary Ethernet protocol spoken by GE Series 90 / PACSystems / VersaMax PLCs. GE publishes
 * no specification; the on-wire layout used here is the community reverse-engineering (Collin Matthews'
 * `TheMadHatt3r/ge-ethernet-SRTP`; the New Haven "Leveraging the SRTP protocol …" paper).
 *
 * Every message begins with a fixed 56-byte header. Only a subset of those 56 bytes has a confidently
 * documented meaning — the message Type, sequence numbers, a controller timestamp, the message-type
 * byte, the mailbox source/destination, packet counters, and the service-request block (Service Request
 * Code, segment selector / memory type, memory offset, data length). Everything else in the header is
 * "reserved/unknown" and is kept verbatim as hex so it round-trips untouched. A READ request is exactly
 * the 56-byte header; a response carries the read data after the header, so any bytes captured past the
 * 56-byte header are kept verbatim as `payload` hex (bounded by the captured TCP payload).
 *
 * ⚠️ The two-octet memory-offset and data-length fields are LITTLE-ENDIAN (segment selector / SNP
 * addressing convention: LSB first). There is no little-endian helper in this codebase, so those uint16
 * fields are read/written byte-by-byte in their closures. Every numeric field is a clamped uint (never a
 * hard enum) so any value that decodes off the wire re-encodes without an Ajv rejection.
 */
export class GESRTP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (GESRTP.#schemaCache ??= GESRTP.#buildSchema())
    }

    /** A little-endian unsigned 16-bit field of 2 octets at `offset` (LSB first, then MSB). */
    static #fieldUInt16LE(name: string, offset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 65535,
            decode: function (this: GESRTP): void {
                const b: Buffer = this.readBytes(offset, 2)
                ;(this.instance as any)[name].setValue(b[0] | (b[1] << 8))
            },
            encode: function (this: GESRTP): void {
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > 65535) {
                    this.recordError(node.getPath(), 'Maximum value is 65535')
                    value = 65535
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(offset, Buffer.from([value & 0xff, (value >> 8) & 0xff]))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'GE-SRTP type=${type} svc=${serviceRequestCode}',
            properties: {
                //Byte 0: message Type (0x02 transmit/request, 0x03 return; 0x01 seen on responses).
                type: this.fieldUInt('type', 0, 1, 'Type'),
                //Byte 1: reserved/unknown, kept verbatim.
                reserved1: this.fieldHex('reserved1', 1, 1, 'Reserved (1)'),
                //Byte 2: sequence number.
                sequenceNumber: this.fieldUInt('sequenceNumber', 2, 1, 'Sequence Number'),
                //Byte 3: reserved/unknown.
                reserved3: this.fieldHex('reserved3', 3, 1, 'Reserved (3)'),
                //Byte 4: text length (documented single byte; the wider framing is unknown).
                textLength: this.fieldUInt('textLength', 4, 1, 'Text Length'),
                //Bytes 5..25: reserved/unknown span, kept verbatim (21 octets).
                reserved5: this.fieldHex('reserved5', 5, 21, 'Reserved (5..25)'),
                //Bytes 26..28: controller timestamp echoed in the header.
                timeSeconds: this.fieldUInt('timeSeconds', 26, 1, 'Time Seconds'),
                timeMinutes: this.fieldUInt('timeMinutes', 27, 1, 'Time Minutes'),
                timeHours: this.fieldUInt('timeHours', 28, 1, 'Time Hours'),
                //Byte 29: reserved/unknown.
                reserved29: this.fieldHex('reserved29', 29, 1, 'Reserved (29)'),
                //Byte 30: sequence number (repeated).
                sequenceNumber2: this.fieldUInt('sequenceNumber2', 30, 1, 'Sequence Number (repeated)'),
                //Byte 31: message-type byte (0xC0 observed on requests).
                messageType: this.fieldUInt('messageType', 31, 1, 'Message Type'),
                //Bytes 32..35: mailbox source, kept verbatim.
                mailboxSource: this.fieldHex('mailboxSource', 32, 4, 'Mailbox Source'),
                //Bytes 36..39: mailbox destination, kept verbatim.
                mailboxDestination: this.fieldHex('mailboxDestination', 36, 4, 'Mailbox Destination'),
                //Byte 40: packet number.
                packetNumber: this.fieldUInt('packetNumber', 40, 1, 'Packet Number'),
                //Byte 41: total packet count.
                totalPacketNumber: this.fieldUInt('totalPacketNumber', 41, 1, 'Total Packet Number'),
                //Byte 42: Service Request Code (0x04 read sys memory, 0x07 write sys memory, 0x00 status …).
                serviceRequestCode: this.fieldUInt('serviceRequestCode', 42, 1, 'Service Request Code'),
                //Byte 43: segment selector / memory type (0x08 %R, 0x0A %AI, 0x10 %I …), request-dependent.
                segmentSelector: this.fieldUInt('segmentSelector', 43, 1, 'Segment Selector'),
                //Bytes 44..45: memory offset (LITTLE-ENDIAN; zero-based, i.e. address − 1).
                memoryOffset: this.#fieldUInt16LE('memoryOffset', 44, 'Memory Offset'),
                //Bytes 46..47: data length (LITTLE-ENDIAN; count of the addressed units).
                dataLength: this.#fieldUInt16LE('dataLength', 46, 'Data Length'),
                //Bytes 48..55: remaining request-dependent / reserved header octets, kept verbatim.
                reserved48: this.fieldHex('reserved48', 48, 8, 'Reserved (48..55)'),
                //Anything captured after the fixed 56-byte header (e.g. a read response's data), kept
                //verbatim and bounded by the captured TCP payload so it never reads past the buffer.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: GESRTP): void {
                        const remaining: number = this.packet.length - this.startPos
                        this.instance.payload.setValue(remaining > 56 ? BufferToHex(this.readBytes(56, remaining - 56)) : '')
                    },
                    encode: function (this: GESRTP): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(56, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'gesrtp'

    public readonly name: string = 'GE-SRTP'

    public readonly nickname: string = 'GESRTP'

    public readonly matchKeys: string[] = ['tcpport:18245']

    public match(): boolean {
        //GE-SRTP rides on TCP port 18245. The header carries no strong content magic (byte 0 is only
        //0x00..0x03), so the well-known port is the signature: require the full fixed 56-byte header to
        //be present before claiming the payload.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        return this.packet.length - this.startPos >= 56
    }

    //A leaf header — the response data body is service-request-code dependent and not sub-decoded.
    public readonly demuxProducers: DemuxProducer[] = []

}
