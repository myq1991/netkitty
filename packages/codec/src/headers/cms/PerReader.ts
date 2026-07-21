/**
 * PerReader — a clamping, never-throwing bit cursor for ASN.1 ALIGNED BASIC-PER (ITU-T X.691 / GB/T
 * 16263.2), used to decode the CMS (DL/T 2811-2024) service data area for DISPLAY. It reads from a
 * Buffer with a bit position and octet-aligns on demand. Past the end of the buffer every read returns
 * zero/empty rather than throwing, so a truncated or mis-typed frame degrades gracefully (the CMS layer
 * keeps the raw bytes verbatim as the authoritative encode form regardless).
 *
 * ALIGNED-PER rules implemented here (the parts CMS ACSI needs):
 *  - a constrained INTEGER whose range ≤ 255 packs in ceil(log2(range)) bits with NO alignment;
 *  - a constrained INTEGER whose range is larger, and every length determinant, OCTET/BIT STRING and
 *    character-string content, octet-aligns first;
 *  - a length determinant is 1 octet when < 128, else 2 octets (top bits 10) up to 16383 (fragmentation
 *    for larger values is reported so the caller can bail to verbatim).
 */
export class PerReader {

    readonly #buf: Buffer
    #bit: number

    constructor(buf: Buffer) {
        this.#buf = buf
        this.#bit = 0
    }

    /** Current byte position (rounded down). */
    bytePos(): number {
        return this.#bit >> 3
    }

    /** Bits still available. */
    bitsRemaining(): number {
        return this.#buf.length * 8 - this.#bit
    }

    /** Read one bit (0 past the end). */
    readBit(): number {
        if (this.#bit >= this.#buf.length * 8) {
            this.#bit++
            return 0
        }
        const byte: number = this.#buf[this.#bit >> 3]
        const bit: number = (byte >> (7 - (this.#bit & 7))) & 1
        this.#bit++
        return bit
    }

    /** Read n bits as an unsigned number (n ≤ 32; 0 past the end). */
    readBits(n: number): number {
        let value: number = 0
        for (let i: number = 0; i < n; i++) value = (value << 1) | this.readBit()
        return value >>> 0
    }

    /** Advance to the next octet boundary. */
    align(): void {
        if (this.#bit & 7) this.#bit = (this.#bit + 7) & ~7
    }

    /** Read n whole octets (octet-aligns first). Clamps the returned slice to the buffer; the cursor still
     *  advances the full n octets so repeated past-the-end reads stay monotonic (never rewind). */
    readOctets(n: number): Buffer {
        this.align()
        const start: number = this.#bit >> 3
        const end: number = start + n
        this.#bit = end * 8
        const sliceStart: number = start > this.#buf.length ? this.#buf.length : start
        const sliceEnd: number = end > this.#buf.length ? this.#buf.length : end
        return this.#buf.subarray(sliceStart, sliceEnd < sliceStart ? sliceStart : sliceEnd)
    }

    /**
     * A constrained INTEGER in [lb, ub], ALIGNED-PER (X.691 §11.5.7): range==1 → 0 bits (the value is lb);
     * range ≤ 255 → the minimal bit-field, no alignment; range == 256 → one octet-aligned octet; range in
     * 257..65536 → two octet-aligned octets; range > 65536 → a length determinant (octet count) then that
     * many octet-aligned octets (§11.5.7.4). Multiplication is used for the octet accumulation so 32-bit
     * values do not overflow a shift.
     */
    readConstrainedInt(lb: number, ub: number): number {
        const range: number = ub - lb + 1
        if (range <= 1) return lb
        if (range < 256) {
            let bits: number = 0
            while ((1 << bits) < range) bits++
            return lb + this.readBits(bits)
        }
        if (range === 256) return lb + (this.readOctets(1)[0] ?? 0)
        if (range <= 65536) {
            const two: Buffer = this.readOctets(2)
            return lb + (((two[0] ?? 0) << 8) | (two[1] ?? 0))
        }
        //range > 65536: length-determinant-prefixed minimal-octet form, octet-aligned.
        const length: {value: number, fragmented: boolean} = this.readLengthDeterminant()
        if (length.fragmented) return lb
        const buf: Buffer = this.readOctets(length.value)
        let value: number = 0
        for (let i: number = 0; i < buf.length; i++) value = (value * 256) + buf[i]
        return lb + value
    }

    /**
     * A general length determinant (X.691 §10.9). Octet-aligns first. Returns {value, fragmented}: 1 octet
     * for 0..127, 2 octets for 128..16383, otherwise the fragmented form (16k-block count) which the
     * caller should treat as "bail to verbatim".
     */
    readLengthDeterminant(): {value: number, fragmented: boolean} {
        this.align()
        const first: number = this.readOctets(1)[0] ?? 0
        if ((first & 0x80) === 0) return {value: first & 0x7f, fragmented: false}
        if ((first & 0xc0) === 0x80) {
            const second: number = this.readOctets(1)[0] ?? 0
            return {value: ((first & 0x3f) << 8) | second, fragmented: false}
        }
        //Fragmented (top bits 11): the low 6 bits × 16384 is the first block size; not fully decoded here.
        return {value: (first & 0x3f) * 16384, fragmented: true}
    }

    /** A VisibleString / character string with a length determinant then octet-aligned content. */
    readLengthPrefixedString(): string {
        const length: {value: number, fragmented: boolean} = this.readLengthDeterminant()
        if (length.fragmented) return ''
        return this.readOctets(length.value).toString('latin1')
    }

    /**
     * Read n characters of a known-multiplier character string (8 bits/char in ALIGNED-PER, e.g.
     * VisibleString). Aligned-PER octet-aligns the content, EXCEPT a fixed string whose whole size is ≤ 16
     * bits packs its 8-bit chars contiguously with no alignment (X.691 small-string exception). Pass
     * aligned=false for that case.
     */
    readCharString(n: number, aligned: boolean): string {
        if (aligned) return this.readOctets(n).toString('latin1')
        let out: string = ''
        for (let i: number = 0; i < n; i++) out += String.fromCharCode(this.readBits(8))
        return out
    }

    /**
     * Read a fixed-size BIT STRING of `nBits` bits, returning it as hex, the bits left-aligned (MSB first)
     * into ceil(nBits/8) octets with trailing zero padding — the usual BIT STRING display form. Pass
     * aligned=true (octet-align the content first) for strings wider than 16 bits; ≤16-bit fixed strings
     * pack unaligned (X.691 small-string exception).
     */
    readBitString(nBits: number, aligned: boolean): string {
        if (aligned) this.align()
        const out: Buffer = Buffer.alloc(Math.ceil(nBits / 8))
        for (let i: number = 0; i < nBits; i++) {
            if (this.readBit()) out[i >> 3] |= 0x80 >> (i & 7)
        }
        return out.toString('hex')
    }
}
