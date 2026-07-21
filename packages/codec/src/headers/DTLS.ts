import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BufferToUInt16} from '../helper/BufferToNumber'
import {UInt16ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * DTLS — Datagram Transport Layer Security (RFC 6347), the datagram-oriented sibling of TLS carried over
 * UDP. Its record layer mirrors TLS's but adds explicit anti-replay sequencing: every record begins with a
 * fixed 13-byte header — ContentType(1) + Version(2) + Epoch(2) + SequenceNumber(6) + Length(2) — followed
 * by the `Length`-byte Fragment. ContentType names the sub-protocol (20 change_cipher_spec, 21 alert,
 * 22 handshake, 23 application_data, 24 heartbeat); Version is 0xfeff for DTLS 1.0 or 0xfefd for DTLS 1.2
 * (deliberately ~ the ones-complement of the TLS version so the two never collide). Epoch counts cipher
 * changes and SequenceNumber is a 48-bit per-epoch counter.
 *
 * DTLS has no single well-known UDP port (it underlies WebRTC, CoAP-over-DTLS, OpenVPN-style tunnels,
 * etc.), so this header is bucketed on udp:443 yet opts into the content-heuristic fallback: its record
 * header is a strong signature (ContentType in 20..25 AND Version feff/fefd) that lets it be recognized on
 * any UDP port. This is a minimal record-layer slice: it structures one record header and keeps the
 * Fragment verbatim as hex (bounded by `Length` and the UDP payload); the Fragment's sub-protocol
 * (handshake / alert / …) and any second pipelined record in the same datagram are left to later
 * enrichment / the codec's recursion (a leaf advances only over its own record). The Length is honored
 * when supplied (a crafted record may lie) else derived from the Fragment; a well-formed record
 * round-trips byte-for-byte.
 */
export class DTLS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (DTLS.#schemaCache ??= DTLS.#buildSchema())
    }

    /**
     * Bytes available to this record, bounded by the enclosing UDP payload (udp.length - 8) so a lying
     * Length near the end of the datagram cannot read into a trailing record / padding, and so the
     * Fragment stops at the datagram boundary rather than swallowing the whole captured buffer.
     */
    #available(): number {
        let available: number = this.packet.length - this.startPos
        const prev: any = this.prevCodecModule
        if (prev && prev.id === 'udp') {
            const udpPayload: number = prev.instance.length.getValue(0) - 8
            if (udpPayload >= 0 && udpPayload < available) available = udpPayload
        }
        return available < 0 ? 0 : available
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'DTLS type=${contentType} len=${length}',
            properties: {
                //ContentType (20 change_cipher_spec, 21 alert, 22 handshake, 23 application_data,
                //24 heartbeat). Kept as an integer — the record header is otherwise opaque here.
                contentType: this.fieldUInt('contentType', 0, 1, 'Content Type'),
                //Version — 0xfeff DTLS 1.0 / 0xfefd DTLS 1.2. Stored as a lower-case hex string so any
                //value round-trips verbatim (the match gate restricts real selection to feff/fefd).
                version: this.fieldHex('version', 1, 2, 'Version'),
                epoch: this.fieldUInt('epoch', 3, 2, 'Epoch'),
                //48-bit per-epoch sequence number, kept verbatim as hex (exceeds the 32-bit fieldUInt path).
                sequenceNumber: this.fieldHex('sequenceNumber', 5, 6, 'Sequence Number'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: DTLS): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(11, 2)))
                    },
                    encode: function (this: DTLS): void {
                        //Honored when supplied (a crafted record may lie); else derived from the Fragment.
                        const provided: number | undefined = this.instance.length.getValue()
                        let value: number = (provided !== undefined && provided !== null)
                            ? provided
                            : HexToBuffer(this.instance.fragment.getValue('')).length
                        if (value > 65535) {
                            this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                            value = 65535
                        }
                        if (value < 0) {
                            this.recordError(this.instance.length.getPath(), 'Minimum value is 0')
                            value = 0
                        }
                        this.instance.length.setValue(value)
                        this.writeBytes(11, UInt16ToBuffer(value))
                    }
                },
                //The record Fragment (the sub-protocol payload), kept verbatim. Bounded by the decoded
                //Length and the UDP payload, so trailing / pipelined records are left to the codec's
                //recursion (a leaf record does not re-match itself — its parent is no longer UDP).
                fragment: {
                    type: 'string',
                    label: 'Fragment',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: DTLS): void {
                        const available: number = this.#available()
                        const maxFragment: number = available - 13
                        let fragmentLength: number = this.instance.length.getValue(0)
                        if (maxFragment <= 0) fragmentLength = 0
                        else if (fragmentLength > maxFragment) fragmentLength = maxFragment
                        this.instance.fragment.setValue(fragmentLength > 0 ? BufferToHex(this.readBytes(13, fragmentLength)) : '')
                    },
                    encode: function (this: DTLS): void {
                        const fragment: string = this.instance.fragment.getValue('')
                        if (fragment) this.writeBytes(13, HexToBuffer(fragment))
                    }
                }
            }
        }
    }

    public readonly id: string = 'dtls'

    public readonly name: string = 'Datagram Transport Layer Security'

    public readonly nickname: string = 'DTLS'

    //Bucketed on the common DTLS-over-HTTPS port; heuristicFallback keeps it recognized on any other UDP
    //port via its record-header signature (DTLS has no single well-known port).
    public readonly matchKeys: string[] = ['udpport:443']

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        //DTLS rides UDP. Require the full 13-byte record header within the UDP payload, a ContentType in
        //the DTLS sub-protocol range (20..25), and a DTLS 1.0/1.2 Version (feff/fefd) — a distinctive
        //two-field signature so non-DTLS UDP traffic (on 443 or elsewhere) falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        if (this.#available() < 13) return false
        const contentType: number = this.readBytes(0, 1, true)[0]
        if (contentType < 20 || contentType > 25) return false
        const version: string = BufferToHex(this.readBytes(1, 2, true))
        return version === 'feff' || version === 'fefd'
    }

    //A leaf header — the record Fragment's sub-protocol is kept verbatim for now.
    public readonly demuxProducers: DemuxProducer[] = []

}
