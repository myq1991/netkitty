import {DNS} from './DNS'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'

/** A decoded DNS name {value, raw} — mirrors DNS's internal type (value = readable, raw = wire bytes). */
type DnsName = {value: string, raw: string}

/**
 * NBNS — NetBIOS Name Service (RFC 1002), the NetBIOS-over-TCP/IP name service on UDP 137. The message
 * uses the DNS wire format (RFC 1035): the same 12-byte header, questions, and resource records with
 * label compression — so it reuses the DNS decode/encode wholesale.
 *
 * The one NBNS-specific twist is the name: a NetBIOS name is a 16-byte value (15-byte name + 1-byte
 * suffix) carried in a single DNS label of length 32 via "first-level encoding" (RFC 1001 §4.1) — each
 * of the 16 bytes is split into two nibbles, each offset by 'A' (0x41) into a printable byte. This
 * subclass overrides readName/writeName to present the readable "NAME<suffix>" form while re-emitting
 * the exact wire bytes (`raw`) for a byte-perfect round-trip; crafting from `value` re-encodes the
 * first-level form. Everything else (header bits, counts, RR structure, compression) is inherited DNS.
 */
export class NBNS extends DNS {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (NBNS.#schemaCache ??= {...super.SCHEMA, summary: 'NBNS ${id} queries=${qdcount} answers=${ancount}'})
    }

    /** Decode a 32-char first-level-encoded label into "NAME<XX>" (suffix in hex). Non-32-char labels pass through. */
    static #decodeNetBIOSName(label: string): string {
        if (label.length !== 32) return label
        const bytes: number[] = []
        for (let i: number = 0; i < 32; i += 2) {
            const high: number = (label.charCodeAt(i) - 0x41) & 0x0f
            const low: number = (label.charCodeAt(i + 1) - 0x41) & 0x0f
            bytes.push((high << 4) | low)
        }
        const buffer: Buffer = Buffer.from(bytes)
        const name: string = buffer.subarray(0, 15).toString('latin1').replace(/ +$/, '')
        return `${name}<${buffer[15].toString(16).padStart(2, '0')}>`
    }

    /** Encode "NAME<XX>" back to a 32-char first-level-encoded label. Non-matching values pass through. */
    static #encodeNetBIOSName(value: string): string {
        const match: RegExpMatchArray | null = value.match(/^(.*)<([0-9a-fA-F]{2})>$/)
        if (!match) return value
        const buffer: Buffer = Buffer.alloc(16, 0x20)
        Buffer.from(match[1], 'latin1').copy(buffer, 0, 0, 15)
        buffer[15] = parseInt(match[2], 16)
        let out: string = ''
        for (const octet of buffer) {
            out += String.fromCharCode(0x41 + ((octet >> 4) & 0x0f))
            out += String.fromCharCode(0x41 + (octet & 0x0f))
        }
        return out
    }

    protected readName(offset: number): {name: DnsName, next: number} {
        const result: {name: DnsName, next: number} = super.readName(offset)
        const parts: string[] = result.name.value.split('.')
        parts[0] = NBNS.#decodeNetBIOSName(parts[0])
        return {name: {value: parts.join('.'), raw: result.name.raw}, next: result.next}
    }

    protected writeName(offset: number, name: DnsName | undefined): number {
        //Byte-perfect for a decoded name: re-emit the exact wire bytes.
        if (name && name.raw) return super.writeName(offset, name)
        //Crafted from value: first-level-encode the NetBIOS name label, then let DNS build the labels.
        const value: string = name && name.value ? name.value : ''
        const parts: string[] = value.split('.')
        parts[0] = NBNS.#encodeNetBIOSName(parts[0])
        return super.writeName(offset, {value: parts.join('.'), raw: ''})
    }

    public readonly id: string = 'nbns'

    public readonly name: string = 'NetBIOS Name Service'

    public readonly nickname: string = 'NBNS'

    public readonly matchKeys: string[] = ['udpport:137']

    public match(): boolean {
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp'
    }

}
