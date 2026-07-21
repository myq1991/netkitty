import {PerReader} from './PerReader'

/**
 * AsnType — a compact discriminated-union descriptor for the ASN.1 constructs CMS (DL/T 2811-2024) ACSI
 * uses. This lives on the imperative side of the codec's schema split (it is procedural, not serializable
 * JSON Schema) and is interpreted by {@link PerDecoder} against ALIGNED BASIC-PER bytes. Descriptors are
 * transcribed per service from the spec's §7/§8 and kept in a name→type table so recursive types
 * (`Data`, object references) resolve through `{k: 'ref'}`.
 */
export type AsnType =
    | {k: 'bool'}
    | {k: 'int', lb?: number, ub?: number}
    | {k: 'enum', values: string[], ext?: boolean}
    | {k: 'bitstr', size?: number}
    | {k: 'octstr', size?: number}
    | {k: 'vstr', min?: number, max?: number}
    | {k: 'seq', ext?: boolean, fields: AsnField[]}
    | {k: 'seqof', element: AsnType}
    | {k: 'choice', ext?: boolean, alts: {name: string, type: AsnType}[]}
    | {k: 'ref', name: string}

export interface AsnField {
    name: string
    type: AsnType
    optional?: boolean
    default?: unknown
}

export type AsnTypeTable = Record<string, AsnType>

/**
 * PerDecoder — a never-throwing ALIGNED BASIC-PER interpreter. It walks an {@link AsnType} descriptor,
 * pulling from a {@link PerReader}, and returns a plain JS value tree for DISPLAY only (CMS keeps the raw
 * service-data bytes as the authoritative encode form, so this decoder never affects output bytes). When it
 * meets something it cannot safely decode — a fragmented length, an unknown `ref`, or an extensible type
 * whose additions are present — it sets {@link bailed} so the caller can fall back to showing raw hex.
 */
export class PerDecoder {

    static readonly #MAX_DEPTH: number = 64

    readonly #reader: PerReader
    readonly #table: AsnTypeTable
    #bailed: boolean
    #depth: number

    constructor(buf: Buffer, table: AsnTypeTable = {}) {
        this.#reader = new PerReader(buf)
        this.#table = table
        this.#bailed = false
        this.#depth = 0
    }

    /** True once the decoder hit a construct it could not safely decode; the result is then incomplete. */
    get bailed(): boolean {
        return this.#bailed
    }

    /** Bytes consumed so far (rounded down) — lets the caller show any trailing bytes as raw. */
    get bytePos(): number {
        return this.#reader.bytePos()
    }

    decode(type: AsnType): unknown {
        return this.#decode(type)
    }

    #decode(type: AsnType): unknown {
        if (this.#depth >= PerDecoder.#MAX_DEPTH) {
            //Runaway recursion (a malformed/pathological descriptor): stop rather than overflow the stack.
            this.#bailed = true
            return undefined
        }
        this.#depth++
        try {
            return this.#dispatch(type)
        } finally {
            this.#depth--
        }
    }

    #dispatch(type: AsnType): unknown {
        switch (type.k) {
            case 'bool':
                return this.#reader.readBit() === 1
            case 'int':
                return this.#decodeInt(type)
            case 'enum':
                return this.#decodeEnum(type)
            case 'bitstr':
            case 'octstr':
                return this.#decodeString(type)
            case 'vstr':
                return this.#decodeVisibleString(type)
            case 'seq':
                return this.#decodeSequence(type)
            case 'seqof':
                return this.#decodeSequenceOf(type)
            case 'choice':
                return this.#decodeChoice(type)
            case 'ref':
                return this.#decodeRef(type)
        }
    }

    #decodeInt(type: {lb?: number, ub?: number}): number {
        if (type.lb !== undefined && type.ub !== undefined) return this.#reader.readConstrainedInt(type.lb, type.ub)
        //Unconstrained / semi-constrained: a length determinant then that many octets, octet-aligned.
        const length: {value: number, fragmented: boolean} = this.#reader.readLengthDeterminant()
        if (length.fragmented) {
            this.#bailed = true
            return 0
        }
        const octets: Buffer = this.#reader.readOctets(length.value)
        if (octets.length === 0) return type.lb ?? 0
        //Beyond 6 octets a JS number loses integer precision (>2^53); flag the result incomplete rather
        //than mis-display it (a BigInt path is a prerequisite for shipping 64-bit Data CHOICE leaves).
        if (octets.length > 6) this.#bailed = true
        let value: number = 0
        for (let i: number = 0; i < octets.length; i++) value = (value * 256) + octets[i]
        //Semi-constrained (lb..MAX): the octets are the unsigned value offset by the lower bound.
        if (type.lb !== undefined) return type.lb + value
        //Fully unconstrained INTEGER: the octets are a two's-complement signed value.
        if (octets[0] & 0x80) value -= Math.pow(2, octets.length * 8)
        return value
    }

    #decodeEnum(type: {values: string[], ext?: boolean}): string | number {
        if (type.ext && this.#reader.readBit() === 1) {
            //An extension addition: index is a normally-small-non-negative number we do not decode.
            this.#bailed = true
            return ''
        }
        const idx: number = this.#reader.readConstrainedInt(0, type.values.length - 1)
        return type.values[idx] ?? idx
    }

    #decodeString(type: {k: 'bitstr' | 'octstr', size?: number}): string {
        let count: number
        if (type.size !== undefined) {
            count = type.k === 'bitstr' ? Math.ceil(type.size / 8) : type.size
        } else {
            const length: {value: number, fragmented: boolean} = this.#reader.readLengthDeterminant()
            if (length.fragmented) {
                this.#bailed = true
                return ''
            }
            count = type.k === 'bitstr' ? Math.ceil(length.value / 8) : length.value
        }
        return this.#reader.readOctets(count).toString('hex')
    }

    #decodeVisibleString(type: {min?: number, max?: number}): string {
        if (type.min !== undefined && type.max !== undefined) {
            //Fixed size: no length field. Content octet-aligns unless the whole string is ≤ 16 bits
            //(X.691 small-string exception — 8 bits/char, so a 1- or 2-char fixed string packs unaligned).
            if (type.max === type.min) return this.#reader.readCharString(type.min, type.min * 8 > 16)
            const count: number = this.#reader.readConstrainedInt(type.min, type.max)
            return this.#reader.readOctets(count).toString('latin1')
        }
        return this.#reader.readLengthPrefixedString()
    }

    #decodeSequence(type: {ext?: boolean, fields: AsnField[]}): Record<string, unknown> {
        //Leading extension bit (extensible SEQUENCE): if additions are present we decode the root fields
        //then stop, leaving the additions for the raw-hex fallback.
        let extensions: boolean = false
        if (type.ext) extensions = this.#reader.readBit() === 1
        //Preamble bitmap: one present/absent bit per OPTIONAL / DEFAULT component, in order.
        const optionals: AsnField[] = type.fields.filter((f: AsnField): boolean => !!f.optional || f.default !== undefined)
        const present: Record<string, boolean> = {}
        for (const field of optionals) present[field.name] = this.#reader.readBit() === 1
        const out: Record<string, unknown> = {}
        for (const field of type.fields) {
            const isOptional: boolean = !!field.optional || field.default !== undefined
            if (isOptional && !present[field.name]) {
                if (field.default !== undefined) out[field.name] = field.default
                continue
            }
            out[field.name] = this.#decode(field.type)
        }
        if (extensions) this.#bailed = true
        return out
    }

    #decodeSequenceOf(type: {element: AsnType}): unknown[] {
        const length: {value: number, fragmented: boolean} = this.#reader.readLengthDeterminant()
        if (length.fragmented) {
            this.#bailed = true
            return []
        }
        const out: unknown[] = []
        for (let i: number = 0; i < length.value; i++) {
            if (this.#reader.bitsRemaining() <= 0) {
                this.#bailed = true
                break
            }
            out.push(this.#decode(type.element))
        }
        return out
    }

    #decodeChoice(type: {ext?: boolean, alts: {name: string, type: AsnType}[]}): Record<string, unknown> {
        if (type.ext && this.#reader.readBit() === 1) {
            this.#bailed = true
            return {}
        }
        const idx: number = this.#reader.readConstrainedInt(0, type.alts.length - 1)
        const alt: {name: string, type: AsnType} | undefined = type.alts[idx]
        if (!alt) {
            this.#bailed = true
            return {}
        }
        return {[alt.name]: this.#decode(alt.type)}
    }

    #decodeRef(type: {name: string}): unknown {
        const resolved: AsnType | undefined = this.#table[type.name]
        if (!resolved) {
            this.#bailed = true
            return undefined
        }
        return this.#decode(resolved)
    }
}
