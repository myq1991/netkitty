import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Git Smart Transport over the native `git://` protocol (git-daemon, TCP port 9418). The wire format is
 * a stream of pkt-lines: each pkt-line is a 4-character ASCII hexadecimal length prefix (the length
 * COUNTS those 4 characters) followed by that many minus four bytes of payload; the special value
 * "0000" is a flush-pkt (an empty delimiter, no payload). A git-daemon session opens with a single
 * request pkt-line such as `0032git-upload-pack /project.git\0host=example.com\0` — a length prefix,
 * the service command and repository path, then NUL-delimited extra parameters (host, and for v2 an
 * extra NUL plus capabilities).
 *
 * Like SIP/HTTP, the message body is a text-ish framed stream whose full internal structure (an
 * arbitrary number of pkt-lines, service negotiation, ref advertisements, packfile data) is far richer
 * than a form needs, and byte layout is significant. So the ENTIRE payload of the current segment is
 * kept verbatim as the authoritative `message` field (hex) and re-emitted untouched; only the FIRST
 * pkt-line is parsed on decode into display-only metadata (its declared length and command line).
 * Encode never reconstructs the stream from the parsed fields — it writes `message` back byte-for-byte
 * — so any conformant (or even malformed) git segment round-trips exactly.
 *
 * Note: a git session spans many TCP segments (request, ref advertisement, want/have negotiation, the
 * packfile); reassembly across segments is out of scope. This single-segment codec keeps whatever bytes
 * are present in the current segment verbatim, which is byte-perfect for the single-packet case.
 */
export class GitProtocol extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (GitProtocol.#schemaCache ??= GitProtocol.#buildSchema())
    }

    /**
     * Bytes of this header: git rides on TCP, which has no per-message length, so take the rest of the
     * segment. Stream reassembly across segments is out of scope (see class doc).
     */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /** True if the byte is an ASCII hexadecimal digit (0-9, a-f, A-F) — the pkt-line length alphabet. */
    static #isHexDigit(byte: number): boolean {
        return (byte >= 0x30 && byte <= 0x39) || (byte >= 0x61 && byte <= 0x66) || (byte >= 0x41 && byte <= 0x46)
    }

    /**
     * Parse the first pkt-line into the display-only metadata fields. The first 4 bytes are the ASCII
     * hex length prefix (counting themselves); "0000" is a flush-pkt (length 0, empty command). The
     * command is the pkt-line payload up to the first NUL (for a request pkt-line that is
     * `<service> <path>`). Populated on decode only — these fields have no encode, so they never affect
     * the re-emitted bytes. Never throws: a short/invalid prefix yields length 0 and an empty command.
     */
    #parseFirstPktLine(payload: Buffer): void {
        if (payload.length < 4) {
            this.instance.firstPktLineLength.setValue(0)
            this.instance.firstCommand.setValue('')
            return
        }
        const prefix: string = payload.subarray(0, 4).toString('latin1')
        const declared: number = parseInt(prefix, 16)
        const length: number = Number.isNaN(declared) ? 0 : declared
        this.instance.firstPktLineLength.setValue(length)
        //flush-pkt (0000) or a length that does not exceed the prefix itself carries no payload.
        if (length <= 4) {
            this.instance.firstCommand.setValue('')
            return
        }
        let end: number = length
        if (end > payload.length) end = payload.length
        const body: Buffer = payload.subarray(4, end)
        //The command is the text up to the first NUL (extra parameters follow NUL-delimited).
        const nul: number = body.indexOf(0x00)
        const command: Buffer = nul >= 0 ? body.subarray(0, nul) : body
        this.instance.firstCommand.setValue(command.toString('latin1'))
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Git ${firstCommand}',
            properties: {
                //The whole segment payload is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any git segment). The first pkt-line is parsed
                //into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: GitProtocol): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseFirstPktLine(Buffer.alloc(0))
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseFirstPktLine(raw)
                    },
                    encode: function (this: GitProtocol): void {
                        //Re-emit the authoritative message verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the first pkt-line on decode (no encode — populated by
                //the message field above, never read back). firstPktLineLength is the declared 4-hex-char
                //length prefix; firstCommand is the pkt-line payload up to the first NUL (the service
                //command + repository path for a request line).
                firstPktLineLength: {type: 'integer', label: 'First pkt-line Length', minimum: 0, maximum: 65535},
                firstCommand: {type: 'string', label: 'First Command'}
            }
        }
    }

    public readonly id: string = 'git'

    public readonly name: string = 'Git Smart Protocol'

    public readonly nickname: string = 'Git'

    public readonly matchKeys: string[] = ['tcpport:9418']

    public match(): boolean {
        //Git rides on TCP port 9418 (git-daemon) as a pkt-line stream. Port 9418 is dedicated to git,
        //but require the pkt-line signature — at least a 4-byte ASCII-hex length prefix — so non-git
        //traffic on the port falls through to raw rather than claiming an un-decodable text layer. Text
        //protocols do not open a heuristicFallback, so this stays port-bucketed.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() < 4) return false
        const prefix: Buffer = this.readBytes(0, 4, true)
        for (let i: number = 0; i < 4; i++) {
            if (!GitProtocol.#isHexDigit(prefix[i])) return false
        }
        return true
    }

    //A leaf header — the pkt-line stream (ref advertisement, negotiation, packfile) is a higher-layer
    //concern and spans multiple segments; the payload is kept verbatim as `message`.
    public readonly demuxProducers: DemuxProducer[] = []

}
