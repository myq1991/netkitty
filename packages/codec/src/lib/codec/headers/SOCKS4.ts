import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'
import {BufferToIPv4} from '../../helper/BufferToIP'
import {IPv4ToBuffer} from '../../helper/IPToBuffer'

/**
 * SOCKS4 — the SOCKS Protocol Version 4 (and the SOCKS4a extension), carried over TCP well-known
 * port 1080. Only two message shapes travel on the wire, discriminated by their leading octet:
 *
 *   1. Client request : version(1,=4) · command(1: 1 CONNECT / 2 BIND) · dstPort(2, BE) ·
 *                        dstIp(4, IPv4) · userId(null-terminated ASCII) [· domain(null-terminated)]
 *   2. Server reply   : null(1,=0) · status(1: 0x5A granted, 0x5B/0x5C/0x5D rejected) ·
 *                        dstPort(2, BE) · dstIp(4, IPv4)   — always exactly 8 octets
 *
 * The two shapes share their tail exactly — dstPort at offset 2 and dstIp at offset 4 — so those
 * fields are common to both; only the leading octet (version 4 vs null 0), the second octet
 * (command vs status), and the request's trailing user-id are shape-specific. A `messageType`
 * display field ('request' | 'reply') is the discriminator, decoded from the leading octet
 * (4 → request, 0 → reply) and driving every field below.
 *
 * SOCKS4a: when the request's dstIp is 0.0.0.x (first three octets zero, last non-zero) the client
 * could not resolve the host and appends a second null-terminated string — the destination domain —
 * after the user-id. The codec structures that trailing string as `domain` whenever bytes remain
 * after the user-id's terminator, so both plain SOCKS4 and SOCKS4a requests round-trip byte-for-byte.
 * (A request whose user-id lacks its RFC-mandated null terminator is malformed: it decodes
 * best-effort but re-emits with the terminator, so the byte-perfect guarantee is for conformant
 * SOCKS4 only.)
 *
 * Matching rationale (NO heuristicFallback): SOCKS4 is claimed ONLY on the tcp:1080 bucket. Its only
 * content signature is a single leading octet of 0x04 (request) or 0x00 (reply) — a signature that
 * matches enormous amounts of arbitrary binary TCP data; recognition therefore depends entirely on
 * the well-known port. Joining the global content-heuristic chain would mislabel unrelated binary
 * traffic on any port, so SOCKS4 is confined to tcp:1080 and alt-port SOCKS4 falls losslessly to raw.
 */
export class SOCKS4 extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SOCKS4.#schemaCache ??= SOCKS4.#buildSchema())
    }

    /** Bytes available to this header: SOCKS4 rides on TCP, which has no per-message length. */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /** True when the leading octet marks a client request (version 4) rather than a server reply. */
    #isRequest(): boolean {
        return (this.instance.messageType.getValue('request') as string) === 'request'
    }

    /**
     * Read a null-terminated latin1 string at `offset` (bounded by the captured length); returns its
     * value plus the offset one past the terminator (or the end of buffer if never terminated).
     */
    #readCString(offset: number, available: number): {value: string, next: number} {
        let p: number = offset
        while (p < available && this.readBytes(p, 1, true)[0] !== 0) p++
        const value: string = p > offset ? this.readBytes(offset, p - offset).toString('latin1') : ''
        let next: number = p
        if (p < available) {
            this.readBytes(p, 1) //consume the null terminator (extends headerLength)
            next = p + 1
        }
        return {value: value, next: next}
    }

    /** Write a latin1 string plus its null terminator at `offset`; returns the offset past the terminator. */
    #writeCString(offset: number, value: string): number {
        const bytes: Buffer = Buffer.from(value ? value : '', 'latin1')
        this.writeBytes(offset, bytes)
        this.writeBytes(offset + bytes.length, Buffer.from([0]))
        return offset + bytes.length + 1
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SOCKS4 ${messageType}',
            properties: {
                //Discriminator + display field. Decoded from the leading octet (4 → request, 0 →
                //reply); on encode it is supplied by the input (default 'request') and read by every
                //field below to decide which bytes it owns.
                messageType: {
                    type: 'string',
                    label: 'Message Type',
                    enum: ['request', 'reply'],
                    default: 'request',
                    decode: function (this: SOCKS4): void {
                        const lead: number = this.#payloadLength() >= 1 ? this.readBytes(0, 1, true).readUInt8(0) : 4
                        this.instance.messageType.setValue(lead === 0 ? 'reply' : 'request')
                    }
                },
                //Leading octet, common to both shapes: 0x04 for a request, 0x00 (the "null" byte) for
                //a reply. Structured for both so the common tail (port, ip) sits at fixed offsets.
                version: {
                    type: 'integer',
                    label: 'Version',
                    minimum: 0,
                    maximum: 255,
                    default: 4,
                    decode: function (this: SOCKS4): void {
                        this.instance.version.setValue(this.readBytes(0, 1).readUInt8(0))
                    },
                    encode: function (this: SOCKS4): void {
                        const node: any = this.instance.version
                        let value: number = node.getValue(this.#isRequest() ? 4 : 0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 255) {
                            this.recordError(node.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBytes(0, Buffer.from([value]))
                    }
                },
                //REQUEST shape: the SOCKS command at offset 1 (1 = CONNECT, 2 = BIND).
                command: {
                    type: 'integer',
                    label: 'Command',
                    enum: [1, 2],
                    minimum: 0,
                    maximum: 255,
                    default: 1,
                    decode: function (this: SOCKS4): void {
                        if (!this.#isRequest()) {
                            this.instance.command.setValue(1)
                            return
                        }
                        this.instance.command.setValue(this.readBytes(1, 1).readUInt8(0))
                    },
                    encode: function (this: SOCKS4): void {
                        if (!this.#isRequest()) return
                        const node: any = this.instance.command
                        let value: number = node.getValue(1, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 255) {
                            this.recordError(node.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBytes(1, Buffer.from([value]))
                    }
                },
                //REPLY shape: the reply status code at offset 1 (0x5A granted, 0x5B request rejected
                //or failed, 0x5C/0x5D identd failures).
                status: {
                    type: 'integer',
                    label: 'Status',
                    enum: [0x5a, 0x5b, 0x5c, 0x5d],
                    minimum: 0,
                    maximum: 255,
                    default: 0x5a,
                    decode: function (this: SOCKS4): void {
                        if (this.#isRequest()) {
                            this.instance.status.setValue(0x5a)
                            return
                        }
                        this.instance.status.setValue(this.readBytes(1, 1).readUInt8(0))
                    },
                    encode: function (this: SOCKS4): void {
                        if (this.#isRequest()) return
                        const node: any = this.instance.status
                        let value: number = node.getValue(0x5a, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (value > 255) {
                            this.recordError(node.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBytes(1, Buffer.from([value]))
                    }
                },
                //Common to both shapes: the destination (request) / bound (reply) port at offset 2,
                //big-endian.
                dstPort: {
                    type: 'integer',
                    label: 'Destination Port',
                    minimum: 0,
                    maximum: 65535,
                    default: 0,
                    decode: function (this: SOCKS4): void {
                        this.instance.dstPort.setValue(this.#payloadLength() >= 4 ? BufferToUInt16(this.readBytes(2, 2)) : 0)
                    },
                    encode: function (this: SOCKS4): void {
                        const node: any = this.instance.dstPort
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
                        this.writeBytes(2, UInt16ToBuffer(value))
                    }
                },
                //Common to both shapes: the destination (request) / bound (reply) IPv4 address at
                //offset 4. A request whose first three octets are zero and last non-zero is SOCKS4a
                //(the real host is carried by the trailing `domain`).
                dstIp: {
                    type: 'string',
                    label: 'Destination IP',
                    default: '0.0.0.0',
                    decode: function (this: SOCKS4): void {
                        this.instance.dstIp.setValue(this.#payloadLength() >= 8 ? BufferToIPv4(this.readBytes(4, 4)) : '0.0.0.0')
                    },
                    encode: function (this: SOCKS4): void {
                        const value: string = this.instance.dstIp.getValue('0.0.0.0')
                        this.writeBytes(4, IPv4ToBuffer(value ? value : '0.0.0.0'))
                    }
                },
                //REQUEST shape: the null-terminated user-id (SOCKS4 authentication identifier) at
                //offset 8. Kept verbatim (latin1) and re-emitted with its null terminator.
                userId: {
                    type: 'string',
                    label: 'User ID',
                    default: '',
                    decode: function (this: SOCKS4): void {
                        if (!this.#isRequest()) {
                            this.instance.userId.setValue('')
                            return
                        }
                        const available: number = this.#payloadLength()
                        this.instance.userId.setValue(this.#readCString(8, available).value)
                    },
                    encode: function (this: SOCKS4): void {
                        if (!this.#isRequest()) return
                        this.#writeCString(8, this.instance.userId.getValue(''))
                    }
                },
                //REQUEST shape (SOCKS4a): the null-terminated destination domain that follows the
                //user-id when the client could not resolve the host (dstIp 0.0.0.x). Structured
                //whenever bytes remain after the user-id terminator, so SOCKS4a round-trips exactly.
                domain: {
                    type: 'string',
                    label: 'Domain',
                    default: '',
                    decode: function (this: SOCKS4): void {
                        if (!this.#isRequest()) {
                            this.instance.domain.setValue('')
                            return
                        }
                        const available: number = this.#payloadLength()
                        const afterUser: number = this.#readCString(8, available).next
                        this.instance.domain.setValue(afterUser < available ? this.#readCString(afterUser, available).value : '')
                    },
                    encode: function (this: SOCKS4): void {
                        if (!this.#isRequest()) return
                        const domain: string = this.instance.domain.getValue('')
                        if (!domain) return
                        const userBytes: Buffer = Buffer.from(this.instance.userId.getValue('') as string, 'latin1')
                        this.#writeCString(8 + userBytes.length + 1, domain)
                    }
                }
            }
        }
    }

    public readonly id: string = 'socks4'

    public readonly name: string = 'SOCKS4'

    public readonly nickname: string = 'SOCKS4'

    //SOCKS4 is recognized ONLY on the well-known port 1080 — deliberately NOT via heuristicFallback.
    //Its only content signature is a single leading 0x04/0x00 octet, which matches vast amounts of
    //arbitrary binary TCP data; recognition depends entirely on the port bucket. See the class doc.
    public readonly matchKeys: string[] = ['tcpport:1080']

    public match(): boolean {
        //Port-bucket (tcp:1080) + leading-octet signature. Reached only on the tcp:1080 bucket.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        const available: number = this.#payloadLength()
        //A reply is exactly 8 octets; a request is at least 9 (its user-id contributes a terminator).
        //Require the 8-octet common span and a leading 0x04 (request) or 0x00 (reply).
        if (available < 8) return false
        const lead: number = this.readBytes(0, 1, true).readUInt8(0)
        return lead === 4 || lead === 0
    }

    //A leaf header — SOCKS4 tunnels an arbitrary application stream once the request is granted; its
    //relayed payload is not demuxed off this header.
    public readonly demuxProducers: DemuxProducer[] = []

}
