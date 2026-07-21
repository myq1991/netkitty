import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt8} from '../helper/BufferToNumber'
import {UInt8ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * GELF — Graylog Extended Log Format, the log-shipping payload Graylog and its inputs exchange over
 * UDP port 12201. A GELF UDP datagram carries a single log message in one of three on-wire forms, told
 * apart by the first bytes of the payload:
 *
 *  - Chunked (magic 0x1E0F): a large message split across datagrams. The 12-byte chunk header is the
 *    2-byte magic, an 8-byte Message ID (shared by all chunks of one message), a 1-byte Sequence Number
 *    (this chunk's index) and a 1-byte Sequence Count (total chunks), followed by this chunk's slice of
 *    the (possibly compressed) message. The receiver reassembles the slices by Message ID / Sequence.
 *  - GZIP (magic 0x1F8B): the whole datagram is a single gzip-compressed GELF JSON document.
 *  - Uncompressed: anything else — the datagram is the GELF JSON document as UTF-8 text (a `{ ... }`
 *    object). (A zlib-deflated document, magic 0x78, also falls here and is kept verbatim.)
 *
 * This is the minimal faithful slice: the form is detected from the leading magic and the chunk header
 * is structured (magic / messageId / sequenceNumber / sequenceCount + chunk `data` hex); the gzip body
 * and the uncompressed/zlib body are opaque here and kept verbatim (`payload` / `message` hex) — the
 * chunk-reassembly, gunzip and JSON decoding are a later enrichment layered on top of this byte-perfect
 * base. Everything is bounded by the enclosing UDP payload length so a trailing FCS/padding is not
 * absorbed. Nothing is recomputed on encode (the Sequence Count is honored, not derived), so a
 * well-formed datagram of any form round-trips byte-for-byte. `form` is a decode-time discriminant that
 * writes no bytes; on encode it is honored when supplied, else inferred from which fields are present.
 */
export class GELF extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (GELF.#schemaCache ??= GELF.#buildSchema())
    }

    /** End of this datagram within the captured bytes: bounded by the parent UDP payload (udp.length − 8). */
    #payloadEnd(): number {
        let end: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpLength: number = prev.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < end) end = udpLength - 8
        }
        return end < 0 ? 0 : end
    }

    /** Detect the on-wire form from the leading magic bytes of the payload. */
    #detectForm(): string {
        const end: number = this.#payloadEnd()
        if (end < 2) return 'uncompressed'
        const lead: Buffer = this.readBytes(0, 2, true)
        if (lead[0] === 0x1e && lead[1] === 0x0f) return 'chunked'
        if (lead[0] === 0x1f && lead[1] === 0x8b) return 'gzip'
        return 'uncompressed'
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'GELF ${form}',
            properties: {
                //Discriminant chosen at decode from the leading magic (chunked / gzip / uncompressed).
                //It writes no bytes; on encode it is honored when supplied, else inferred from which
                //form-specific fields are present (a chunk has a Message ID; a gzip form has payload).
                //No enum: it never gates re-encoding of a decoded value.
                form: {
                    type: 'string',
                    label: 'Form',
                    decode: function (this: GELF): void {
                        this.instance.form.setValue(this.#detectForm())
                    },
                    encode: function (this: GELF): void {
                        let form: string | undefined = this.instance.form.getValue()
                        if (!form) {
                            if (this.instance.messageId.getValue() !== undefined) form = 'chunked'
                            else if (this.instance.payload.getValue() !== undefined) form = 'gzip'
                            else form = 'uncompressed'
                        }
                        this.instance.form.setValue(form)
                    }
                },
                //Chunked form (magic 0x1E0F). The 12-byte chunk header, structured. Each field acts only
                //when the form is chunked; otherwise it stays unset so it neither decodes phantom values
                //nor writes bytes for the gzip/uncompressed forms.
                magic: {
                    type: 'string',
                    label: 'Magic',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'chunked') return
                        this.instance.magic.setValue(BufferToHex(this.readBytes(0, 2)))
                    },
                    encode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'chunked') return
                        //Honor a supplied magic verbatim (a crafted chunk may lie); else the GELF 0x1E0F.
                        this.writeBytes(0, HexToBuffer(this.instance.magic.getValue('1e0f')))
                    }
                },
                //8-byte Message ID shared by every chunk of one logical message.
                messageId: {
                    type: 'string',
                    label: 'Message ID',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'chunked') return
                        this.instance.messageId.setValue(BufferToHex(this.readBytes(2, 8)))
                    },
                    encode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'chunked') return
                        this.writeBytes(2, HexToBuffer(this.instance.messageId.getValue('0000000000000000')))
                    }
                },
                //This chunk's index (0-based) among the sequence.
                sequenceNumber: {
                    type: 'integer',
                    label: 'Sequence Number',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'chunked') return
                        this.instance.sequenceNumber.setValue(BufferToUInt8(this.readBytes(10, 1)))
                    },
                    encode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'chunked') return
                        const node: any = this.instance.sequenceNumber
                        let value: number = node.getValue(0)
                        if (value > 255) {
                            this.recordError(node.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBytes(10, UInt8ToBuffer(value))
                    }
                },
                //Total number of chunks in the sequence. Honored verbatim (not derived) — a crafted chunk
                //may carry any count.
                sequenceCount: {
                    type: 'integer',
                    label: 'Sequence Count',
                    minimum: 0,
                    maximum: 255,
                    decode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'chunked') return
                        this.instance.sequenceCount.setValue(BufferToUInt8(this.readBytes(11, 1)))
                    },
                    encode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'chunked') return
                        const node: any = this.instance.sequenceCount
                        let value: number = node.getValue(0)
                        if (value > 255) {
                            this.recordError(node.getPath(), 'Maximum value is 255')
                            value = 255
                        }
                        if (value < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        node.setValue(value)
                        this.writeBytes(11, UInt8ToBuffer(value))
                    }
                },
                //This chunk's slice of the (possibly compressed) message, after the 12-byte chunk header.
                //Opaque here (reassembly is deferred); kept verbatim, bounded by the UDP payload.
                data: {
                    type: 'string',
                    label: 'Chunk Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'chunked') return
                        const end: number = this.#payloadEnd()
                        this.instance.data.setValue(end > 12 ? BufferToHex(this.readBytes(12, end - 12)) : '')
                    },
                    encode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'chunked') return
                        const data: string = this.instance.data.getValue('')
                        if (data) this.writeBytes(12, HexToBuffer(data))
                    }
                },
                //GZIP form (magic 0x1F8B): the whole gzip-compressed GELF document, opaque, kept verbatim
                //(magic included) and bounded by the UDP payload.
                payload: {
                    type: 'string',
                    label: 'GZIP Payload',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'gzip') return
                        const end: number = this.#payloadEnd()
                        this.instance.payload.setValue(end > 0 ? BufferToHex(this.readBytes(0, end)) : '')
                    },
                    encode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'gzip') return
                        const payload: string = this.instance.payload.getValue('')
                        if (payload) this.writeBytes(0, HexToBuffer(payload))
                    }
                },
                //Uncompressed form: the GELF JSON document as text (or a zlib-deflated body). Kept verbatim
                //as hex and bounded by the UDP payload, so any body round-trips byte-for-byte.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'uncompressed') return
                        const end: number = this.#payloadEnd()
                        this.instance.message.setValue(end > 0 ? BufferToHex(this.readBytes(0, end)) : '')
                    },
                    encode: function (this: GELF): void {
                        if (this.instance.form.getValue() !== 'uncompressed') return
                        const message: string = this.instance.message.getValue('')
                        if (message) this.writeBytes(0, HexToBuffer(message))
                    }
                }
            }
        }
    }

    public readonly id: string = 'gelf'

    public readonly name: string = 'Graylog Extended Log Format'

    public readonly nickname: string = 'GELF'

    public readonly matchKeys: string[] = ['udpport:12201']

    public match(): boolean {
        //GELF rides on UDP well-known port 12201 (the matchKeys bucket selects it). The uncompressed
        //form is arbitrary JSON with no fixed magic, so the port is the signature; require at least one
        //payload byte so an empty datagram falls through to raw rather than claiming an empty layer.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        return this.#payloadEnd() >= 1
    }

    //A leaf header — chunk reassembly, gunzip and GELF JSON decoding are deferred to a later slice.
    public readonly demuxProducers: DemuxProducer[] = []

}
