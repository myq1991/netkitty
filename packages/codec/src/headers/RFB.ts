import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** The 4-byte signature that opens every RFB stream ("RFB " — the ProtocolVersion handshake prefix). */
const RFB_SIGNATURE: string = 'RFB '

/** The ProtocolVersion handshake is a fixed 12-byte line: `RFB ` + 3-digit major `.` 3-digit minor + `\n`. */
const RFB_VERSION_LENGTH: number = 12

/**
 * RFB / VNC — the Remote Framebuffer Protocol (RFC 6143), the wire protocol behind VNC, carried over TCP
 * well-known port 5900. A connection OPENS with a 12-byte ProtocolVersion handshake: the US-ASCII line
 * `"RFB 003.008\n"` (or 003.003 / 003.007) — exactly `RFB ` then a 3-digit major, a dot, a 3-digit minor,
 * and a trailing `\n`. After that come binary security/init messages and then the (complex, stateful)
 * framebuffer-update protocol.
 *
 * MINIMAL slice: this codec structures ONLY the clean, self-identifying text part — the 12-byte
 * ProtocolVersion handshake — into display-only metadata {isVersionHandshake, versionString, major,
 * minor}. Everything else (the post-handshake binary messages) is kept verbatim; structuring those is a
 * later slice. Like the text protocols (HTTP/SIP/FTP), the ENTIRE raw payload is the single source of
 * truth: it is decoded verbatim to hex in the `message` field and re-emitted byte-for-byte on encode —
 * the parsed metadata carry no codec of their own and never reconstruct the bytes. So any RFB payload
 * (version handshake, binary message, or truncated fragment) round-trips exactly.
 *
 * Matching is deliberately PORT-CONFINED to tcp:5900 with NO heuristicFallback. The 12-byte "RFB xxx.yyy\n"
 * greeting is a strong, distinctive signature, but the post-handshake RFB messages are opaque binary with
 * no reliable content signature — they cannot be recognized off-port without over-claiming arbitrary TCP
 * traffic. So the tcp:5900 bucket is the whole scope: on that bucket a leading "RFB " (with >=12 bytes) is
 * a version handshake and any other payload is kept as verbatim RFB `data`. Off port 5900, even an
 * "RFB "-looking payload falls losslessly to raw (see the port-confinement test). This mirrors FTP's
 * bucket-only confinement, for the same "the tail is ambiguous, so trust the port" reason.
 *
 * Note: reassembly across TCP segments is out of scope. This single-segment codec keeps whatever bytes
 * are present verbatim, which is byte-perfect for the single-packet case.
 */
export class RFB extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (RFB.#schemaCache ??= RFB.#buildSchema())
    }

    /**
     * Bytes of this header: RFB rides on TCP, which has no per-message length, so take the rest of the
     * segment. Reassembly across segments is out of scope (see class doc).
     */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /**
     * Parse the display-only metadata from the raw payload. When the payload opens with the "RFB "
     * signature and is at least a full 12-byte ProtocolVersion line, it is a version handshake: the
     * version string ("RFB 003.008") and its numeric major/minor are extracted (best-effort — a
     * malformed greeting yields 0). Otherwise it is a post-handshake binary message kept as verbatim
     * `data`; versionString is set to the literal 'data' so the summary reads "VNC data". Populated on
     * decode only — these fields have no encode, so they never affect the re-emitted bytes.
     */
    #parseVersion(raw: Buffer): void {
        //A ProtocolVersion handshake is exactly the 12-byte "RFB xxx.yyy\n" form (RFC 6143 §7.1.1, LF only).
        //Require the full pattern to match — a 12-byte payload that merely starts with "RFB " but is not a
        //well-formed version line (garbage digits, or a CRLF terminator) is NOT flagged as a handshake, so
        //the display metadata never claims a version it could not parse.
        const line: string = raw.length >= RFB_VERSION_LENGTH ? raw.subarray(0, RFB_VERSION_LENGTH).toString('latin1') : ''
        const match: RegExpMatchArray | null = line.match(/^RFB (\d{3})\.(\d{3})\n$/)
        if (match) {
            this.instance.isVersionHandshake.setValue(true)
            //The version string is the greeting without its trailing newline, e.g. "RFB 003.008".
            this.instance.versionString.setValue(line.replace(/[\r\n]+$/, ''))
            this.instance.major.setValue(Number(match[1]))
            this.instance.minor.setValue(Number(match[2]))
            return
        }
        this.instance.isVersionHandshake.setValue(false)
        //Non-handshake payload: the summary tail is the literal 'data' (produces "VNC data").
        this.instance.versionString.setValue('data')
        this.instance.major.setValue(0)
        this.instance.minor.setValue(0)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'VNC ${versionString}',
            properties: {
                //The whole raw payload is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any RFB payload). When it is a ProtocolVersion
                //handshake the leading line is parsed into the display-only metadata below, which carry
                //no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: RFB): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseVersion(Buffer.alloc(0))
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseVersion(raw)
                    },
                    encode: function (this: RFB): void {
                        //Re-emit the authoritative payload verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the ProtocolVersion handshake on decode (no encode —
                //populated by the message field above, never read back). isVersionHandshake distinguishes
                //the opening 12-byte version line from any other (binary) RFB payload; versionString/major/
                //minor describe the version when it is a handshake.
                isVersionHandshake: {type: 'boolean', label: 'Is Version Handshake'},
                versionString: {type: 'string', label: 'Version String'},
                major: {type: 'integer', label: 'Major Version', minimum: 0, maximum: 999},
                minor: {type: 'integer', label: 'Minor Version', minimum: 0, maximum: 999}
            }
        }
    }

    public readonly id: string = 'rfb'

    public readonly name: string = 'RFB (VNC)'

    public readonly nickname: string = 'VNC'

    //RFB/VNC is recognized ONLY on the well-known port 5900 — deliberately NOT via heuristicFallback.
    //The 12-byte "RFB xxx.yyy\n" greeting is distinctive, but the post-handshake RFB messages are opaque
    //binary with no content signature, so they can only be claimed by trusting the port. Confining to the
    //tcp:5900 bucket keeps that safe: off-port traffic (even an "RFB "-looking payload) never reaches this
    //bucket and falls losslessly to raw.
    public readonly matchKeys: string[] = ['tcpport:5900']

    public match(): boolean {
        //Reached only on the tcp:5900 bucket. A leading "RFB " with a full 12-byte line is a version
        //handshake; any other payload on this port-confined bucket is kept as verbatim RFB data. Either
        //way a non-empty payload over TCP is claimed (byte-perfect), and an empty payload is not.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        const available: number = this.#payloadLength()
        if (available < 1) return false
        const lead: string = this.readBytes(0, 4, true).toString('latin1')
        if (lead === RFB_SIGNATURE && available >= RFB_VERSION_LENGTH) return true
        return available >= 1
    }

    //A leaf header — the post-handshake RFB message stream is a higher-layer concern (a later slice).
    public readonly demuxProducers: DemuxProducer[] = []

}
