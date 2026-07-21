import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * rsync — the rsync daemon protocol (TCP port 873). A session opens with a US-ASCII text handshake: the
 * server sends a greeting line `@RSYNCD: <version>\n` (e.g. `@RSYNCD: 31.0\n`, LF-terminated, no CR), the
 * client echoes its own `@RSYNCD: <version>\n`, then the client sends the module name and options as text
 * lines, after which the connection switches to a binary multiplexed stream (4-byte tag/length framed
 * messages) for the actual file-list / delta transfer.
 *
 * The post-handshake binary multiplexing is stateful and cross-message (tag demux, per-tag length,
 * reassembly across segments), and even the text phase carries significant whitespace / ordering, far
 * richer than a form needs. So, like SIP/HTTP/Finger, the ENTIRE raw payload is kept verbatim as the
 * authoritative `message` field (hex) and re-emitted untouched — byte-perfect for any rsync segment,
 * text handshake or binary frame alike. When the payload begins with the `@RSYNCD:` greeting signature,
 * its first line is additionally parsed into display-only metadata (isGreeting + version); those fields
 * carry no codec of their own and never affect the re-emitted bytes.
 */
export class Rsync extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Rsync.#schemaCache ??= Rsync.#buildSchema())
    }

    /**
     * Bytes of this header: rsync rides on TCP, which has no per-message length, so take the rest of the
     * segment. The binary multiplexed framing (and reassembly across segments) is out of scope; whatever
     * bytes are present in the current segment are kept verbatim.
     */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /** The first line of the payload (up to the first LF, or the whole payload if none); a trailing CR is stripped. */
    static #firstLine(text: string): string {
        const idx: number = text.indexOf('\n')
        let line: string = idx >= 0 ? text.slice(0, idx) : text
        if (line.endsWith('\r')) line = line.slice(0, -1)
        return line
    }

    /**
     * Parse the first line into the display-only metadata. Only a line beginning with the `@RSYNCD:`
     * signature is a greeting; its remainder (trimmed) is the protocol version token (e.g. "31.0", or a
     * status word like "OK"/"AUTHREQD ..."). Populated on decode only — these fields have no encode, so
     * they never affect the re-emitted bytes. Never throws: a non-greeting payload yields empty metadata.
     */
    #parseFirstLine(text: string): void {
        const line: string = Rsync.#firstLine(text)
        if (line.startsWith('@RSYNCD:')) {
            this.instance.isGreeting.setValue(true)
            this.instance.version.setValue(line.slice('@RSYNCD:'.length).trim())
            return
        }
        this.instance.isGreeting.setValue(false)
        this.instance.version.setValue('')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'rsync ${version}',
            properties: {
                //The whole raw payload is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any rsync segment). The greeting line, when
                //present, is parsed into the display-only metadata below, which carry no codec.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: Rsync): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseFirstLine('')
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseFirstLine(raw.toString('latin1'))
                    },
                    encode: function (this: Rsync): void {
                        //Re-emit the authoritative payload verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the first line on decode (no encode — populated by the
                //message field above, never read back). isGreeting is true only for a `@RSYNCD:` line;
                //version is the token after `@RSYNCD:` (empty for a binary/non-greeting segment).
                isGreeting: {type: 'boolean', label: 'Is Greeting'},
                version: {type: 'string', label: 'Version'}
            }
        }
    }

    public readonly id: string = 'rsync'

    public readonly name: string = 'Rsync Daemon Protocol'

    public readonly nickname: string = 'RSYNC'

    public readonly matchKeys: string[] = ['tcpport:873']

    public match(): boolean {
        //rsync rides on TCP port 873. The payload has no fixed content magic once the connection turns
        //binary, so the well-known port is the signature (no heuristicFallback: it is not claimed on any
        //other port). Require the previous layer to be TCP and at least one payload byte to be present.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        return this.#payloadLength() > 0
    }

    //A leaf header — the binary multiplexed stream that follows the handshake is a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
