import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt32} from '../helper/BufferToNumber'
import {UInt32ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** Kafka's default socket.request.max.bytes (100 MiB). A MessageSize beyond this is implausible. */
const KAFKA_MAX_MESSAGE_SIZE: number = 104857600

/**
 * Apache Kafka wire protocol, TCP port 9092. Every Kafka message is length-prefixed: a big-endian uint32
 * MessageSize counting the number of bytes that FOLLOW it, then the message. A REQUEST message begins with
 * a request header — apiKey (2, BE) + apiVersion (2, BE) + correlationId (4, BE) + clientId (a nullable
 * string: a 2-byte BE length, -1 meaning null, then that many UTF-8 bytes) + [tagged fields on flexible
 * versions] + the request body. A RESPONSE begins with correlationId (4, BE) + body.
 *
 * ⚠️ Request vs response is NOT self-describing on the wire: telling them apart needs the paired
 * connection state (which apiKey/apiVersion a given correlationId was requested with), which is
 * cross-packet state — out of scope for this single-packet codec. This codec therefore assumes REQUEST
 * framing: that is what a client sends, it is the more identifiable of the two (a response is just
 * correlationId + opaque body), and it is the common client-side case. A captured response would be
 * mis-labeled — a documented limitation of the minimal slice.
 *
 * As a REQUEST, this codec structures MessageSize + apiKey + apiVersion + correlationId and keeps the rest
 * (clientId + optional tagged fields + body) verbatim as `payload` hex (byte-perfect), bounded by
 * MessageSize (the message ends at offset 4 + MessageSize) and the captured bytes — so a pipelined second
 * message or trailing bytes are left to the codec's recursion / RawData. The MessageSize is honored when
 * supplied (a crafted message may lie), else derived as 8 (apiKey + apiVersion + correlationId) + payload
 * bytes. A well-formed request round-trips byte-for-byte. Structuring clientId / tagged fields / the
 * per-apiKey body is a later slice.
 */
export class Kafka extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Kafka.#schemaCache ??= Kafka.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Kafka apiKey=${apiKey}',
            properties: {
                //Big-endian uint32: the count of bytes that FOLLOW this field (apiKey + apiVersion +
                //correlationId + payload). Honored when supplied (a crafted message may lie); else derived
                //as 8 (the fixed apiKey + apiVersion + correlationId header) + payload bytes.
                messageSize: {
                    type: 'integer',
                    label: 'Message Size',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: Kafka): void {
                        this.instance.messageSize.setValue(BufferToUInt32(this.readBytes(0, 4)))
                    },
                    encode: function (this: Kafka): void {
                        const provided: number | undefined = this.instance.messageSize.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : 8 + HexToBuffer(this.instance.payload.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.messageSize.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.messageSize.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.messageSize.setValue(value)
                        this.writeBytes(0, UInt32ToBuffer(value))
                    }
                },
                apiKey: this.fieldUInt('apiKey', 4, 2, 'API Key'),
                apiVersion: this.fieldUInt('apiVersion', 6, 2, 'API Version'),
                correlationId: this.fieldUInt('correlationId', 8, 4, 'Correlation ID'),
                //The rest of the request (clientId + optional tagged fields + body) after the 12-byte
                //MessageSize/apiKey/apiVersion/correlationId prefix, kept verbatim. Bounded by MessageSize
                //(the message ends at offset 4 + MessageSize) and the captured bytes, so trailing/pipelined
                //data is left to the codec's recursion / RawData.
                payload: {
                    type: 'string',
                    label: 'Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: Kafka): void {
                        const remaining: number = this.packet.length - this.startPos
                        const messageSize: number = this.instance.messageSize.getValue(0)
                        let end: number = 4 + messageSize
                        if (end > remaining) end = remaining
                        this.instance.payload.setValue(end > 12 ? BufferToHex(this.readBytes(12, end - 12)) : '')
                    },
                    encode: function (this: Kafka): void {
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(12, HexToBuffer(payload))
                    }
                }
            }
        }
    }

    public readonly id: string = 'kafka'

    public readonly name: string = 'Kafka'

    public readonly nickname: string = 'Kafka'

    public readonly matchKeys: string[] = ['tcpport:9092']

    public match(): boolean {
        //Kafka rides on TCP port 9092. The length prefix is a WEAK content signature (any big-endian
        //uint32 followed by bytes looks like it), so this stays a port-bucket protocol: matchKeys only,
        //NO heuristicFallback — we never claim Kafka off port 9092 on the strength of a plausible length.
        //Within the bucket, require the full 12-byte minimal request header (MessageSize + apiKey +
        //apiVersion + correlationId) and a plausible MessageSize (large enough to cover the 8-byte
        //apiKey/apiVersion/correlationId that MessageSize counts, and not absurdly large) so non-Kafka
        //traffic on 9092 falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 12) return false
        const messageSize: number = BufferToUInt32(this.readBytes(0, 4, true))
        if (messageSize < 8) return false
        return messageSize <= KAFKA_MAX_MESSAGE_SIZE
    }

    //A leaf header — clientId / tagged fields / the per-apiKey body require flexible-version and
    //cross-message parsing kept verbatim as payload for now.
    public readonly demuxProducers: DemuxProducer[] = []

}
