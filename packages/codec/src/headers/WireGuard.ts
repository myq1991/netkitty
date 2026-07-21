import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * WireGuard (the WireGuard protocol, RFC-less / Noise_IKpsk2), UDP — commonly port 51820 but the port is
 * freely configurable per-peer. Every WireGuard packet opens with a 4-byte prefix: a 1-byte Message Type
 * (1 = Handshake Initiation, 2 = Handshake Response, 3 = Cookie Reply, 4 = Transport Data) and 3 Reserved
 * bytes that the spec fixes at zero. The remaining layout is entirely Message-Type-driven:
 *
 *   - Type 1 (Handshake Initiation, 148 bytes): sender(4 LE) + ephemeral(32) + static(48) + timestamp(28)
 *                                               + mac1(16) + mac2(16).
 *   - Type 2 (Handshake Response, 92 bytes):    sender(4 LE) + receiver(4 LE) + ephemeral(32) + empty(16)
 *                                               + mac1(16) + mac2(16).
 *   - Type 3 (Cookie Reply, 64 bytes):          receiver(4 LE) + nonce(24) + cookie(32).
 *   - Type 4 (Transport Data, variable):        receiver(4 LE) + counter(8 LE) + encryptedPacket(rest).
 *
 * ⚠️ The sender / receiver indices are LITTLE-ENDIAN uint32 (WireGuard is little-endian on the wire), and
 * there is no little-endian helper in this codebase, so they are read/written byte-by-byte in their
 * closures (`>>> 0` on the WHOLE `|` expression so the high-bit value stays unsigned). The Transport-Data
 * counter is a 64-bit LE nonce counter; it is kept as an 8-byte HEX field rather than a JS number to
 * avoid the >2^53 precision loss (and it round-trips its little-endian bytes verbatim). Every crypto blob
 * (ephemeral/static/timestamp/empty/nonce/cookie/mac1/mac2 and the encrypted payload) is opaque AEAD
 * output, kept verbatim as HEX. A well-formed packet round-trips byte-for-byte.
 *
 * Field presence is branched on Message Type: each field's decode/encode consults a per-type offset table
 * (`#offsetFor`) and no-ops when the field does not belong to the current type, so the four wire formats
 * share one schema without phantom bytes.
 */
export class WireGuard extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (WireGuard.#schemaCache ??= WireGuard.#buildSchema())
    }

    /** Fixed on-wire size of a Message Type with a fixed layout (types 1/2/3); 0 for the variable type 4. */
    static #FIXED_SIZE: Record<number, number> = {1: 148, 2: 92, 3: 64}

    /** The WireGuard payload available in this datagram, clamped by the UDP length (drops trailing FCS/padding). */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /**
     * Header-relative byte offset of `field` for the CURRENT Message Type, or -1 when the field does not
     * belong to this type. Message Type has been decoded (or, on encode, provided) before any other field
     * runs — it is the first schema property — so `instance.messageType` is authoritative here.
     */
    #offsetFor(field: string): number {
        const messageType: number = this.instance.messageType.getValue(0)
        let layout: Record<string, number> | undefined
        switch (messageType) {
            case 1: layout = {sender: 4, ephemeral: 8, static: 40, timestamp: 88, mac1: 116, mac2: 132}; break
            case 2: layout = {sender: 4, receiver: 8, ephemeral: 12, empty: 44, mac1: 60, mac2: 76}; break
            case 3: layout = {receiver: 4, nonce: 8, cookie: 32}; break
            case 4: layout = {receiver: 4, counter: 8}; break
            default: layout = {}
        }
        const offset: number | undefined = layout[field]
        return offset === undefined ? -1 : offset
    }

    /** A little-endian unsigned 32-bit index (sender/receiver) whose offset depends on the Message Type. */
    static #fieldUInt32LE(name: string, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: 4294967295,
            decode: function (this: WireGuard): void {
                const offset: number = this.#offsetFor(name)
                if (offset < 0) return
                const b: Buffer = this.readBytes(offset, 4)
                //`|` yields a signed int32, so apply `>>> 0` to the WHOLE expression to keep the value
                //unsigned — otherwise a high-bit-set index decodes as a negative number.
                ;(this.instance as any)[name].setValue((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0)
            },
            encode: function (this: WireGuard): void {
                const offset: number = this.#offsetFor(name)
                if (offset < 0) return
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > 4294967295) {
                    this.recordError(node.getPath(), 'Maximum value is 4294967295')
                    value = 4294967295
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBytes(offset, Buffer.from([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff]))
            }
        }
    }

    /** A fixed-width opaque crypto blob (HEX) whose offset depends on the Message Type. */
    static #fieldBlob(name: string, byteLength: number, label: string): ProtocolFieldJSONSchema {
        const zero: string = '00'.repeat(byteLength)
        return {
            type: 'string',
            label: label,
            contentEncoding: StringContentEncodingEnum.HEX,
            decode: function (this: WireGuard): void {
                const offset: number = this.#offsetFor(name)
                if (offset < 0) return
                ;(this.instance as any)[name].setValue(BufferToHex(this.readBytes(offset, byteLength)))
            },
            encode: function (this: WireGuard): void {
                const offset: number = this.#offsetFor(name)
                if (offset < 0) return
                this.writeBytes(offset, HexToBuffer((this.instance as any)[name].getValue(zero)))
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'WireGuard type=${messageType}',
            properties: {
                //Message Type first: every other field's presence/offset is branched on it.
                messageType: this.fieldUInt('messageType', 0, 1, 'Message Type'),
                //3 Reserved bytes, spec-fixed at zero. Kept as a field (not asserted) so it is visible/editable;
                //match() requires them zero as part of the content signature, so a non-zero-reserved datagram
                //is not claimed as WireGuard (it falls to raw) rather than round-tripping through this codec.
                reserved: this.fieldHex('reserved', 1, 3, 'Reserved'),
                //Sender index (types 1, 2) — LITTLE-ENDIAN uint32.
                sender: this.#fieldUInt32LE('sender', 'Sender Index'),
                //Receiver index (types 2, 3, 4) — LITTLE-ENDIAN uint32.
                receiver: this.#fieldUInt32LE('receiver', 'Receiver Index'),
                //Handshake crypto blobs (types 1, 2), all opaque AEAD/Curve25519 output kept verbatim.
                ephemeral: this.#fieldBlob('ephemeral', 32, 'Unencrypted Ephemeral'),
                static: this.#fieldBlob('static', 48, 'Encrypted Static'),
                timestamp: this.#fieldBlob('timestamp', 28, 'Encrypted Timestamp'),
                empty: this.#fieldBlob('empty', 16, 'Encrypted Empty'),
                //Cookie Reply blobs (type 3).
                nonce: this.#fieldBlob('nonce', 24, 'Nonce'),
                cookie: this.#fieldBlob('cookie', 32, 'Encrypted Cookie'),
                //Transport Data (type 4): a 64-bit LE counter kept as HEX (avoids >2^53 precision loss) and
                //the encrypted packet — the rest of the datagram, bounded by the UDP length.
                counter: this.#fieldBlob('counter', 8, 'Counter'),
                mac1: this.#fieldBlob('mac1', 16, 'MAC1'),
                mac2: this.#fieldBlob('mac2', 16, 'MAC2'),
                encryptedPacket: {
                    type: 'string',
                    label: 'Encrypted Packet',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: WireGuard): void {
                        const messageType: number = this.instance.messageType.getValue(0)
                        if (messageType !== 4) return
                        const available: number = this.#payloadLength()
                        this.instance.encryptedPacket.setValue(available > 16 ? BufferToHex(this.readBytes(16, available - 16)) : '')
                    },
                    encode: function (this: WireGuard): void {
                        const messageType: number = this.instance.messageType.getValue(0)
                        if (messageType !== 4) return
                        const data: string = this.instance.encryptedPacket.getValue('')
                        if (data) this.writeBytes(16, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 'wireguard'

    public readonly name: string = 'WireGuard'

    public readonly nickname: string = 'WireGuard'

    public readonly matchKeys: string[] = ['udpport:51820']

    public match(): boolean {
        //WireGuard's port is configurable, so this codec is registered ONLY in the udp/51820 demux bucket
        //(no heuristicFallback): the 1-byte Message Type + 3 zero Reserved bytes is a weakish 4-byte content
        //signature that would over-match on arbitrary ports, so the well-known port gates it. Within the
        //bucket, require Message Type ∈ {1,2,3,4}, the 3 Reserved bytes zero, and the fixed-layout types to
        //carry their full length — otherwise fall through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        const available: number = this.#payloadLength()
        if (available < 4) return false
        const messageType: number = this.readBytes(0, 1, true)[0]
        if (messageType < 1 || messageType > 4) return false
        const reserved: Buffer = this.readBytes(1, 3, true)
        if (reserved[0] !== 0 || reserved[1] !== 0 || reserved[2] !== 0) return false
        const fixedSize: number | undefined = WireGuard.#FIXED_SIZE[messageType]
        if (fixedSize !== undefined && available < fixedSize) return false
        //Type 4 needs at least the 16-byte transport header (type+reserved+receiver+counter).
        if (messageType === 4 && available < 16) return false
        return true
    }

    //A leaf header — the payload beyond the header is AEAD-encrypted ciphertext with no further structure.
    public readonly demuxProducers: DemuxProducer[] = []

}
