import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * SOCKS5 — the SOCKS Protocol Version 5 (RFC 1928), carried over TCP well-known port 1080.
 *
 * A SOCKS5 conversation is a short handshake of four message shapes, all beginning with a version octet
 * (0x05):
 *
 *   1. Client greeting          : version(1,=5) · nMethods(1) · methods(nMethods)
 *   2. Server method selection  : version(1,=5) · method(1)
 *   3. Client request           : version(1,=5) · cmd(1) · rsv(1,=0) · atyp(1) · dstAddr(var) · dstPort(2)
 *   4. Server reply             : version(1,=5) · rep(1) · rsv(1,=0) · atyp(1) · bndAddr(var) · bndPort(2)
 *
 * Design choice (documented): only the CLIENT GREETING is fully structured — it is the one message whose
 * length is self-describing (nMethods exactly bounds the methods list), so it can be recognized and split
 * with no ambiguity. The other three shapes carry a conditional, address-type-dependent address whose
 * structuring is a later slice; here they are kept BYTE-VERBATIM after the common version octet as a
 * single `data` hex field. So every SOCKS5 message is: version (structured) + either {nMethods, methods}
 * (greeting) or {data} (everything else). A `messageType` display field ('greeting' | 'other') is the
 * discriminator, and drives the one-line summary. Any well-formed message round-trips byte-for-byte.
 *
 * Greeting recognition is exact: version 5, at least one method offered (nMethods ≥ 1), and the payload
 * length equal to 2 + nMethods (the octets nMethods claims are exactly the octets present). This keeps a
 * two-byte server method-selection (`05 xx`, nMethods would read as 0) out of the greeting shape, and a
 * lying nMethods that over-claims the remaining bytes is NOT mistaken for a greeting — it stays 'other'
 * and is preserved verbatim, so the decoder never trusts nMethods to read past the captured bytes.
 *
 * Matching rationale (NO heuristicFallback): SOCKS5 is claimed ONLY on the tcp:1080 bucket. Its only
 * content signature is a leading 0x05 version octet — a single byte with no further magic, which matches
 * an enormous amount of arbitrary binary TCP data. Recognition therefore depends entirely on the
 * well-known port; joining the global content-heuristic chain would mislabel unrelated binary traffic on
 * any port. Confining SOCKS5 to tcp:1080 keeps that impossible; alt-port SOCKS5 is rare and falls
 * losslessly to raw.
 */
export class SOCKS5 extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SOCKS5.#schemaCache ??= SOCKS5.#buildSchema())
    }

    /** Bytes available to this header: SOCKS5 rides on TCP, which has no per-message length. */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /**
     * True when the payload is a well-formed client greeting: version 5, at least one method offered,
     * and the captured length is exactly 2 + nMethods (nMethods bounds the methods list precisely).
     * Never over-reads: only inspects the first two octets.
     */
    #isGreeting(): boolean {
        const available: number = this.#payloadLength()
        if (available < 3) return false
        const head: Buffer = this.readBytes(0, 2, true)
        if (head.readUInt8(0) !== 5) return false
        const nMethods: number = head.readUInt8(1)
        if (nMethods < 1) return false
        return available === 2 + nMethods
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SOCKS5 ${messageType}',
            properties: {
                //Discriminator + display field. Decoded from the payload shape; on encode it is supplied
                //by the input (default 'other') and read by every field below to decide which bytes it
                //owns. 'greeting' → {version, nMethods, methods}; 'other' → {version, data}.
                messageType: {
                    type: 'string',
                    label: 'Message Type',
                    enum: ['greeting', 'other'],
                    default: 'other',
                    decode: function (this: SOCKS5): void {
                        this.instance.messageType.setValue(this.#isGreeting() ? 'greeting' : 'other')
                    }
                },
                //Common to every SOCKS5 message: the version octet (always 0x05). Structured for both
                //shapes, so the verbatim `data` of a non-greeting holds only the bytes AFTER the version.
                version: {
                    type: 'integer',
                    label: 'Version',
                    minimum: 0,
                    maximum: 255,
                    default: 5,
                    decode: function (this: SOCKS5): void {
                        this.instance.version.setValue(this.readBytes(0, 1).readUInt8(0))
                    },
                    encode: function (this: SOCKS5): void {
                        const node: any = this.instance.version
                        let value: number = node.getValue(5, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
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
                //GREETING shape: the count of authentication methods the client offers.
                nMethods: {
                    type: 'integer',
                    label: 'Number of Methods',
                    minimum: 0,
                    maximum: 255,
                    default: 0,
                    decode: function (this: SOCKS5): void {
                        if ((this.instance.messageType.getValue('other') as string) !== 'greeting') {
                            this.instance.nMethods.setValue(0)
                            return
                        }
                        this.instance.nMethods.setValue(this.readBytes(1, 1).readUInt8(0))
                    },
                    encode: function (this: SOCKS5): void {
                        if ((this.instance.messageType.getValue('other') as string) !== 'greeting') return
                        const node: any = this.instance.nMethods
                        let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
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
                //GREETING shape: the offered method identifiers, kept verbatim as hex. Bounded by nMethods
                //AND by the captured bytes — a lying nMethods can never make this read past the buffer.
                methods: {
                    type: 'string',
                    label: 'Methods',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: SOCKS5): void {
                        if ((this.instance.messageType.getValue('other') as string) !== 'greeting') {
                            this.instance.methods.setValue('')
                            return
                        }
                        const nMethods: number = this.instance.nMethods.getValue(0)
                        const remaining: number = this.#payloadLength() - 2
                        const count: number = nMethods < remaining ? nMethods : (remaining < 0 ? 0 : remaining)
                        this.instance.methods.setValue(count > 0 ? BufferToHex(this.readBytes(2, count)) : '')
                    },
                    encode: function (this: SOCKS5): void {
                        if ((this.instance.messageType.getValue('other') as string) !== 'greeting') return
                        const methods: string = this.instance.methods.getValue('')
                        if (methods) this.writeBytes(2, HexToBuffer(methods))
                    }
                },
                //NON-GREETING shape ('other'): every SOCKS5 message that is not a client greeting
                //(method selection, request, reply) is kept BYTE-VERBATIM after the version octet — from
                //offset 1 to the end of the captured bytes. Structuring the request/reply address is a
                //later slice; this preserves the exact bytes and round-trips them untouched.
                data: {
                    type: 'string',
                    label: 'Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: SOCKS5): void {
                        if ((this.instance.messageType.getValue('other') as string) === 'greeting') {
                            this.instance.data.setValue('')
                            return
                        }
                        const remaining: number = this.#payloadLength() - 1
                        this.instance.data.setValue(remaining > 0 ? BufferToHex(this.readBytes(1, remaining)) : '')
                    },
                    encode: function (this: SOCKS5): void {
                        if ((this.instance.messageType.getValue('other') as string) === 'greeting') return
                        const data: string = this.instance.data.getValue('')
                        if (data) this.writeBytes(1, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 'socks5'

    public readonly name: string = 'SOCKS5'

    public readonly nickname: string = 'SOCKS5'

    //SOCKS5 is recognized ONLY on the well-known port 1080 — deliberately NOT via heuristicFallback. Its
    //only content signature is a single 0x05 version octet, which matches vast amounts of arbitrary
    //binary TCP data; recognition depends entirely on the port bucket. See the class doc for the full
    //rationale.
    public readonly matchKeys: string[] = ['tcpport:1080']

    public match(): boolean {
        //Port-bucket (tcp:1080) + version-5 signature. Reached only on the tcp:1080 bucket.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        const available: number = this.#payloadLength()
        //Every SOCKS5 message is at least 2 octets (version + one more) and starts with version 0x05.
        if (available < 2) return false
        if (this.readBytes(0, 1, true).readUInt8(0) !== 5) return false
        return true
    }

    //A leaf header — SOCKS5 tunnels an arbitrary application stream once the handshake completes; its
    //relayed payload is not demuxed off this header.
    public readonly demuxProducers: DemuxProducer[] = []

}
