import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Memcached — the cache daemon's wire protocol, carried over TCP well-known port 11211. Memcached speaks
 * TWO protocols on the same port, and this codec handles BOTH by branching on the first payload byte
 * (the exact model of the SSH codec, which branches identification-vs-binary on a signature):
 *
 *  1. TEXT protocol (the classic, default). Line-based US-ASCII commands and replies terminated by CR LF:
 *     `get <key>\r\n`, `set <key> <flags> <exptime> <bytes>\r\n<data>\r\n`, and replies such as
 *     `VALUE <key> <flags> <bytes>\r\n<data>\r\nEND\r\n`, `STORED\r\n`, `END\r\n`, … Like the other
 *     US-ASCII line protocols in this codec (POP3/FTP/SIP/HTTP), the exact bytes a peer sees are richer
 *     than any structure a form needs (arbitrary keys, inline data blocks, pipelined commands), so the
 *     ENTIRE payload is kept verbatim as the authoritative `message` field (hex) and re-emitted untouched;
 *     only the leading token is parsed on decode into the display-only `command` field (get/set/VALUE/
 *     STORED/…). Encode never reconstructs the payload from `command` — it writes `message` back
 *     byte-for-byte, so any conformant (or malformed) text exchange round-trips exactly.
 *
 *  2. BINARY protocol (RFC-less, memcached's binary framing). A fixed 24-byte header —
 *     magic(1: 0x80 request / 0x81 response) · opcode(1) · keyLength(2, BE) · extrasLength(1) ·
 *     dataType(1) · vbucket-id/status(2, BE) · totalBodyLength(4, BE) · opaque(4) · cas(8) — followed by
 *     `totalBodyLength` bytes of body (extras + key + value). This codec structures the 24-byte header as
 *     editable fields and keeps the body verbatim as `body` hex, bounded by totalBodyLength (a trailing /
 *     pipelined next message is left to the codec's recursion / RawData). The `cas` field is 8 bytes, so
 *     it is kept as a HEX string (never a JS Number — 8 bytes exceeds 2^53 and would lose precision). A
 *     well-formed binary message round-trips byte-for-byte.
 *
 * Matching rationale (NO heuristicFallback): Memcached is claimed ONLY on the tcp:11211 bucket. The binary
 * header's magic (0x80/0x81) is a weak one-byte signature and the text protocol shares generic verbs
 * (get/set/…) with countless other line protocols, so neither shape carries a signature strong enough to
 * survive the global content-heuristic chain without mislabeling unrelated TCP traffic. Confining
 * Memcached to its well-known port keeps recognition unambiguous; alt-port memcached is rare and falls
 * losslessly to raw.
 */
export class Memcached extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Memcached.#schemaCache ??= Memcached.#buildSchema())
    }

    /** Known Memcached text tokens (client commands + server replies) — used to recognize a text line. */
    static readonly #TEXT_TOKENS: string[] = [
        //Client commands (RFC-less protocol.txt): retrieval, storage, arithmetic, admin, meta.
        'get', 'gets', 'set', 'add', 'replace', 'append', 'prepend', 'cas', 'delete', 'incr', 'decr',
        'touch', 'gat', 'gats', 'stats', 'flush_all', 'version', 'verbosity', 'quit', 'watch', 'lru',
        'lru_crawler', 'me', 'mg', 'ms', 'md', 'mn', 'ma', 'me',
        //Server replies.
        'VALUE', 'END', 'STORED', 'NOT_STORED', 'EXISTS', 'NOT_FOUND', 'DELETED', 'TOUCHED', 'OK',
        'STAT', 'VERSION', 'ERROR', 'CLIENT_ERROR', 'SERVER_ERROR', 'RESET', 'BUSY', 'BADCLASS'
    ]

    /** Bytes available to this header: Memcached rides on TCP, which has no per-message length. */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /** True when the payload begins with the binary magic byte (0x80 request / 0x81 response). */
    #isBinaryMagic(): boolean {
        if (this.#payloadLength() < 1) return false
        const first: number = this.readBytes(0, 1, true).readUInt8(0)
        return first === 0x80 || first === 0x81
    }

    /** The leading token of the text payload (up to the first space, CR or LF), or '' if empty. */
    static #leadingToken(text: string): string {
        const line: string = text.split(/[\r\n]/)[0]
        return line.split(' ')[0] || ''
    }

    /**
     * Parse the text payload's leading token into the display-only `command` field and drive the summary.
     * Populated on decode only — `command` has no encode, so it never affects the re-emitted bytes and
     * never mutates `message`. Never throws: an empty payload yields an empty command.
     */
    #parseText(text: string): void {
        const token: string = Memcached.#leadingToken(text)
        this.instance.command.setValue(token)
        this.instance.summaryInfo.setValue(token)
    }

    /**
     * A guarded big-endian unsigned integer field of the BINARY header. It decodes only when the payload
     * is binary (else it resets to 0 so the text view is clean) and encodes only for the binary shape
     * (the text shape's `message` owns those bytes). Wraps BaseHeader.fieldUInt so the offset/width live
     * in one place.
     */
    static #binUInt(name: string, offset: number, byteLength: number, label: string): ProtocolFieldJSONSchema {
        const field: ProtocolFieldJSONSchema = this.fieldUInt(name, offset, byteLength, label)
        field.default = 0
        const rawDecode: (this: Memcached) => void = field.decode as (this: Memcached) => void
        const rawEncode: (this: Memcached) => void = field.encode as (this: Memcached) => void
        field.decode = function (this: Memcached): void {
            if (!this.instance.isBinary.getValue(false)) {
                (this.instance as any)[name].setValue(0)
                return
            }
            rawDecode.call(this)
        }
        field.encode = function (this: Memcached): void {
            if (this.instance.isBinary.getValue(false)) rawEncode.call(this)
        }
        return field
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Memcached ${summaryInfo}',
            properties: {
                //Discriminator between the two on-wire shapes (see class doc). Decoded from the payload's
                //first byte; on encode it is supplied by the input (default false = the TEXT protocol) and
                //read by every field below to decide which bytes it owns. Mirrors SSH.isIdentification.
                isBinary: {
                    type: 'boolean',
                    label: 'Is Binary',
                    default: false,
                    decode: function (this: Memcached): void {
                        this.instance.isBinary.setValue(this.#isBinaryMagic())
                    }
                },
                //BINARY 24-byte header. magic(0x80 req / 0x81 resp), opcode, keyLength(BE), extrasLength,
                //dataType, vbucket-id/status(BE), totalBodyLength(BE), opaque, cas(8 bytes → HEX).
                magic: Memcached.#binUInt('magic', 0, 1, 'Magic'),
                opcode: Memcached.#binUInt('opcode', 1, 1, 'Opcode'),
                keyLength: Memcached.#binUInt('keyLength', 2, 2, 'Key Length'),
                extrasLength: Memcached.#binUInt('extrasLength', 4, 1, 'Extras Length'),
                dataType: Memcached.#binUInt('dataType', 5, 1, 'Data Type'),
                status: Memcached.#binUInt('status', 6, 2, 'VBucket/Status'),
                //totalBodyLength counts the whole body (extras + key + value). Honored on encode when
                //supplied (a crafted message may lie); else derived from the body bytes. No `default` so
                //Ajv leaves it undefined and the derive path can trigger (mirrors ENIP.length).
                totalBodyLength: {
                    type: 'integer',
                    label: 'Total Body Length',
                    minimum: 0,
                    maximum: 4294967295,
                    decode: function (this: Memcached): void {
                        if (!this.instance.isBinary.getValue(false)) {
                            this.instance.totalBodyLength.setValue(0)
                            return
                        }
                        this.instance.totalBodyLength.setValue(this.readBytes(8, 4).readUInt32BE(0))
                    },
                    encode: function (this: Memcached): void {
                        if (!this.instance.isBinary.getValue(false)) return
                        const provided: number | undefined = this.instance.totalBodyLength.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.body.getValue('')).length
                        if (value > 4294967295) {
                            this.recordError(this.instance.totalBodyLength.getPath(), 'Maximum value is 4294967295')
                            value = 4294967295
                        }
                        if (value < 0) {
                            this.recordError(this.instance.totalBodyLength.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.totalBodyLength.setValue(value)
                        const buffer: Buffer = Buffer.alloc(4)
                        buffer.writeUInt32BE(value, 0)
                        this.writeBytes(8, buffer)
                    }
                },
                opaque: Memcached.#binUInt('opaque', 12, 4, 'Opaque'),
                //cas is 8 bytes — an opaque compare-and-swap token. Kept as HEX (never a JS Number: 8
                //bytes exceeds 2^53 and would lose precision). Guarded like the numeric header fields.
                cas: {
                    type: 'string',
                    label: 'CAS',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '0000000000000000',
                    decode: function (this: Memcached): void {
                        if (!this.instance.isBinary.getValue(false)) {
                            this.instance.cas.setValue('0000000000000000')
                            return
                        }
                        this.instance.cas.setValue(BufferToHex(this.readBytes(16, 8)))
                    },
                    encode: function (this: Memcached): void {
                        if (!this.instance.isBinary.getValue(false)) return
                        this.writeBytes(16, HexToBuffer(this.instance.cas.getValue('0000000000000000')))
                    }
                },
                //BINARY body (extras + key + value), kept verbatim. Bounded by totalBodyLength (the body
                //ends at offset 24 + totalBodyLength) and the captured bytes, so a trailing / pipelined
                //next message is left to the codec's recursion / RawData. Also sets the binary summary.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: Memcached): void {
                        if (!this.instance.isBinary.getValue(false)) {
                            this.instance.body.setValue('')
                            return
                        }
                        const remaining: number = this.#payloadLength()
                        const totalBodyLength: number = this.instance.totalBodyLength.getValue(0)
                        let end: number = 24 + totalBodyLength
                        if (end > remaining) end = remaining
                        this.instance.body.setValue(end > 24 ? BufferToHex(this.readBytes(24, end - 24)) : '')
                        this.instance.summaryInfo.setValue(`binary op=${this.instance.opcode.getValue(0)}`)
                    },
                    encode: function (this: Memcached): void {
                        if (!this.instance.isBinary.getValue(false)) return
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(24, HexToBuffer(body))
                    }
                },
                //Display-only text metadata: the leading token of the text payload (populated by the
                //`message` decode below; no encode of its own). Empty for a binary message.
                command: {type: 'string', label: 'Command', default: ''},
                //Drives the one-line summary: the text command, or `binary op=<opcode>` for a binary msg.
                summaryInfo: {type: 'string', label: 'Summary', hidden: true, default: ''},
                //TEXT payload: the whole message kept verbatim (byte-perfect) and re-emitted untouched. The
                //leading token is parsed into `command` on decode; encode never reconstructs from it.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: Memcached): void {
                        if (this.instance.isBinary.getValue(false)) {
                            //Binary shape: no verbatim text; clear the text metadata (summary set by body).
                            this.instance.message.setValue('')
                            this.instance.command.setValue('')
                            return
                        }
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseText('')
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseText(raw.toString('latin1'))
                    },
                    encode: function (this: Memcached): void {
                        //Re-emit the authoritative text payload verbatim — never reconstruct from metadata.
                        if (this.instance.isBinary.getValue(false)) return
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                }
            }
        }
    }

    public readonly id: string = 'memcached'

    public readonly name: string = 'Memcached'

    public readonly nickname: string = 'Memcached'

    //Memcached is recognized ONLY on its well-known port bucket (tcp:11211) — deliberately NOT via
    //heuristicFallback. The binary magic (0x80/0x81) is a weak one-byte signature and the text verbs are
    //shared with many US-ASCII line protocols, so neither shape is distinctive enough for the global
    //content-heuristic chain; the well-known port is the signature. See the class doc for the rationale.
    public readonly matchKeys: string[] = ['tcpport:11211']

    public match(): boolean {
        //Reached only on the tcp:11211 bucket. Confirm the parent is TCP and the payload is either a
        //binary message (magic 0x80/0x81) or a text line whose leading token is a known Memcached verb —
        //so unrelated binary traffic on 11211 still falls through to raw rather than a bogus layer.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        if (this.#payloadLength() < 1) return false
        if (this.#isBinaryMagic()) return true
        const lead: string = this.readBytes(0, 24, true).toString('latin1')
        return Memcached.#TEXT_TOKENS.includes(Memcached.#leadingToken(lead))
    }

    //A leaf header — the memcached session (values, cross-message CAS state) is a higher-layer concern.
    public readonly demuxProducers: DemuxProducer[] = []

}
