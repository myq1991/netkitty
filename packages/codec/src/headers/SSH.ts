import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * SSH — the Secure Shell Transport Layer Protocol (RFC 4253), carried over TCP well-known port 22.
 *
 * An SSH connection has two shapes on the wire, and this codec handles BOTH:
 *
 *  1. Identification string. The very first thing each side sends is a US-ASCII line
 *     `SSH-protoversion-softwareversion[ SP comments]` terminated by CR LF (a lone LF is tolerated),
 *     e.g. `SSH-2.0-OpenSSH_9.6\r\n` (also seen: `SSH-1.99-…` for 2.0 servers that also speak 1.x, and
 *     legacy `SSH-1.5-…`). Like the other US-ASCII line protocols in this codec (HTTP/SIP/FTP), the
 *     structure a form needs is far poorer than the exact bytes a peer sees, so the ENTIRE line is kept
 *     verbatim as the authoritative `message` field (hex) and re-emitted untouched; only the first line
 *     is parsed on decode into display-only metadata (protoVersion/softwareVersion/identString). Encode
 *     never reconstructs the line from those fields — it writes `message` back byte-for-byte.
 *
 *  2. Binary Packet Protocol. After the identifications comes the framed protocol:
 *     `packet_length(4, BE) · padding_length(1) · payload(packet_length - padding_length - 1) ·
 *     padding(padding_length) · MAC(mac_len)`. The MAC is present only once keys are exchanged; the
 *     first binary packet (SSH_MSG_KEXINIT) is sent in cleartext and is readable. This codec keeps the
 *     framing minimal and byte-exact: `packet_length` and `padding_length` are structured, editable
 *     fields, and everything they bound (payload + padding) is kept verbatim as `data` hex. The packet
 *     is bounded by `packet_length + 4` bytes; any MAC/trailing/pipelined bytes are left to the codec's
 *     recursion / RawData (decoding the MAC needs cross-message negotiated cipher/MAC state, which is
 *     out of scope for a single-message codec). A well-formed message round-trips byte-for-byte.
 *
 * Matching rationale (NO heuristicFallback): SSH is claimed ONLY on the tcp:22 bucket. The
 * identification line has a strong, distinctive signature ("SSH-") — but the Binary Packet Protocol has
 * NO content magic at all (a 4-byte length + a padding byte is indistinguishable from arbitrary binary
 * data), so recognizing binary SSH packets relies entirely on the well-known port. Joining the global
 * content-heuristic chain would therefore let SSH mislabel arbitrary binary TCP payloads on any port.
 * Confining SSH to tcp:22 keeps that impossible; alt-port SSH is rare and falls losslessly to raw.
 */
export class SSH extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SSH.#schemaCache ??= SSH.#buildSchema())
    }

    /** Bytes available to this header: SSH rides on TCP, which has no per-message length. */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /** True when the payload begins with the ASCII identification signature "SSH-". */
    #isIdentification(): boolean {
        if (this.#payloadLength() < 4) return false
        return this.readBytes(0, 4, true).toString('latin1') === 'SSH-'
    }

    /**
     * Parse the identification line into the display-only metadata fields. The line is
     * `SSH-<protoversion>-<softwareversion>[ SP comments]` and neither protoversion nor softwareversion
     * may contain '-' (RFC 4253 §4.2), so splitting on '-' is exact. Populated on decode only — these
     * fields have no encode, so they never affect the re-emitted bytes and never mutate `message`.
     * Never throws: a malformed banner yields empty strings.
     */
    #parseIdent(text: string): void {
        //The identification is a single line ended by CR LF (or a lone LF). Keep only up to the first
        //line ending for the display parse; `message` still holds the verbatim bytes.
        let line: string = text
        const lf: number = line.indexOf('\n')
        if (lf >= 0) line = line.slice(0, lf)
        if (line.endsWith('\r')) line = line.slice(0, -1)
        this.instance.identString.setValue(line)
        //`SSH-` then protoversion up to the next '-', then softwareversion up to a space or end-of-line.
        const match: RegExpMatchArray | null = line.match(/^SSH-([^-]*)-([^ ]*)/)
        const protoVersion: string = match ? match[1] : ''
        const softwareVersion: string = match ? match[2] : ''
        this.instance.protoVersion.setValue(protoVersion)
        this.instance.softwareVersion.setValue(softwareVersion)
        this.instance.summaryInfo.setValue(softwareVersion ? softwareVersion : 'identification')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SSH ${summaryInfo}',
            properties: {
                //Discriminator between the two on-wire shapes (see class doc). Decoded from the payload
                //signature; on encode it is supplied by the input (default false = a Binary Packet) and
                //read by every field below to decide which bytes it owns.
                isIdentification: {
                    type: 'boolean',
                    label: 'Is Identification',
                    default: false,
                    decode: function (this: SSH): void {
                        this.instance.isIdentification.setValue(this.#isIdentification())
                    }
                },
                //Display-only metadata parsed from the identification line on decode (no encode —
                //populated by `message` below for the identification shape, empty for a binary packet).
                protoVersion: {type: 'string', label: 'Protocol Version', default: ''},
                softwareVersion: {type: 'string', label: 'Software Version', default: ''},
                identString: {type: 'string', label: 'Identification String', default: ''},
                //Drives the one-line summary: the software version for an identification, else 'packet'.
                summaryInfo: {type: 'string', label: 'Summary', hidden: true, default: ''},
                //IDENTIFICATION shape: the whole line kept verbatim (byte-perfect) and re-emitted
                //untouched. The display metadata above is parsed from it on decode; encode never
                //reconstructs the line from that metadata.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: SSH): void {
                        if (!this.instance.isIdentification.getValue(false)) {
                            //Binary Packet shape: no verbatim line; clear the identification metadata.
                            this.instance.message.setValue('')
                            this.instance.protoVersion.setValue('')
                            this.instance.softwareVersion.setValue('')
                            this.instance.identString.setValue('')
                            this.instance.summaryInfo.setValue('packet')
                            return
                        }
                        const available: number = this.#payloadLength()
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseIdent(raw.toString('latin1'))
                    },
                    encode: function (this: SSH): void {
                        //Only the identification shape owns the whole payload; re-emit it verbatim.
                        if (!this.instance.isIdentification.getValue(false)) return
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //BINARY PACKET shape: packet_length counts padding_length(1) + payload + padding, so the
                //whole message spans packet_length + 4 bytes. Big-endian (unlike ENIP's CIP order).
                packetLength: {
                    type: 'integer',
                    label: 'Packet Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: SSH): void {
                        if (this.instance.isIdentification.getValue(false)) {
                            this.instance.packetLength.setValue(0)
                            return
                        }
                        this.instance.packetLength.setValue(this.readBytes(0, 4).readUInt32BE(0))
                    },
                    encode: function (this: SSH): void {
                        if (this.instance.isIdentification.getValue(false)) return
                        //Honored when supplied (a crafted message may lie); else derived from the data —
                        //packet_length = 1 (padding_length byte) + payload + padding = 1 + data.length.
                        const provided: number | undefined = this.instance.packetLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.data.getValue('')).length + 1
                        if (value > 4294967295) {
                            this.recordError(this.instance.packetLength.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.packetLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.packetLength.setValue(value)
                        const buffer: Buffer = Buffer.alloc(4)
                        buffer.writeUInt32BE(value, 0)
                        this.writeBytes(0, buffer)
                    }
                },
                paddingLength: {
                    type: 'integer',
                    label: 'Padding Length',
                    minimum: 0,
                    maximum: 255,
                    default: 0,
                    decode: function (this: SSH): void {
                        if (this.instance.isIdentification.getValue(false)) {
                            this.instance.paddingLength.setValue(0)
                            return
                        }
                        this.instance.paddingLength.setValue(this.readBytes(4, 1).readUInt8(0))
                    },
                    encode: function (this: SSH): void {
                        if (this.instance.isIdentification.getValue(false)) return
                        const node: any = this.instance.paddingLength
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
                        this.writeBytes(4, Buffer.from([value]))
                    }
                },
                //The payload + padding, kept verbatim. Bounded by packet_length (data ends at offset
                //4 + packet_length) and the captured bytes, so a MAC / trailing / pipelined packet is
                //left to the codec's recursion / RawData.
                data: {
                    type: 'string',
                    label: 'Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: SSH): void {
                        if (this.instance.isIdentification.getValue(false)) {
                            this.instance.data.setValue('')
                            return
                        }
                        const remaining: number = this.#payloadLength()
                        const packetLength: number = this.instance.packetLength.getValue(0)
                        //data spans from offset 5 to 4 + packet_length (i.e. packet_length - 1 bytes).
                        let end: number = 4 + packetLength
                        if (end > remaining) end = remaining
                        this.instance.data.setValue(end > 5 ? BufferToHex(this.readBytes(5, end - 5)) : '')
                    },
                    encode: function (this: SSH): void {
                        if (this.instance.isIdentification.getValue(false)) return
                        const data: string = this.instance.data.getValue('')
                        if (data) this.writeBytes(5, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 'ssh'

    public readonly name: string = 'SSH'

    public readonly nickname: string = 'SSH'

    //SSH is recognized ONLY on the well-known port 22 — deliberately NOT via heuristicFallback. The
    //Binary Packet Protocol has no content magic, so its recognition depends entirely on the port
    //bucket; joining the global heuristic chain would mislabel arbitrary binary TCP traffic. See the
    //class doc for the full rationale.
    public readonly matchKeys: string[] = ['tcpport:22']

    public match(): boolean {
        //Port-bucket + "SSH-" signature. Reached only on the tcp:22 bucket.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        const available: number = this.#payloadLength()
        if (available < 1) return false
        //Identification string: the strong ASCII signature.
        if (this.#isIdentification()) return true
        //Binary Packet Protocol (e.g. a cleartext KEXINIT). No content magic — validate the framing is
        //plausible so genuinely unrelated binary payloads on port 22 still fall through to raw.
        if (available < 6) return false
        const head: Buffer = this.readBytes(0, 5, true)
        const packetLength: number = head.readUInt32BE(0)
        const paddingLength: number = head.readUInt8(4)
        //packet_length counts padding_length(1) + payload + padding; padding is 4..255 (RFC 4253 §6),
        //and 35000 is the minimum max-packet a receiver must support — a generous plausibility ceiling.
        if (packetLength < 5 || packetLength > 35000) return false
        if (paddingLength < 4 || paddingLength > packetLength - 1) return false
        return true
    }

    //A leaf header — the SSH payload (KEXINIT contents, encrypted records, MACs) requires cross-message
    //negotiated cipher state and is a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
