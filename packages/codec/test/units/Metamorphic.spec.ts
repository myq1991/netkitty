import {test} from 'node:test'
import assert from 'node:assert'
import {Codec} from '../../src/Codec'
import {AllPacketFixtureNames, LoadPacket} from '../lib/Fixtures'
import {CodecDecodeResult} from '../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../src/types/CodecEncodeResult'

/**
 * Schema-driven metamorphic test. It explores the input space that hand-made fixtures never cover:
 * for every scalar value field of every fixture, it sets a fresh schema-valid random value and
 * asserts the packet is still a decode/encode FIXED POINT (encode → decode → encode reproduces the
 * bytes). A decode that reads a field from different bits/endianness than encode wrote it breaks
 * that fixed point — this is exactly the asymmetry class (IEC104 IOA endianness, SQ layout, DIQ bit
 * offsets) that byte round-trip over fixtures could not see, caught here from the schema alone.
 */

const codec: Codec = new Codec()
const SCHEMAS: {[id: string]: any} = Object.fromEntries(codec.CODEC_SCHEMAS.map((s: {id: string, schema: unknown}): [string, unknown] => [s.id, s.schema]))

// Fields that control how later bytes are parsed: demux discriminators (etherType is a string and is
// excluded automatically) and header-length. Setting them to an arbitrary value legitimately yields
// an inconsistent packet — the encoder is a faithful executor, not a validator — so they are not
// value fields and are excluded from mutation. Any OTHER structural effect is caught by the shape
// check below, so this list only needs the derived fields the encoder preserves rather than recomputes.
const STRUCTURAL_FIELDS: Set<string> = new Set(['protocol', 'nxt', 'srcport', 'dstport', 'hdrLen'])

function mulberry32(seed: number): () => number {
    let a: number = seed
    return (): number => {
        a |= 0
        a = a + 0x6D2B79F5 | 0
        let t: number = Math.imul(a ^ a >>> 15, 1 | a)
        t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t
        return ((t ^ t >>> 14) >>> 0) / 4294967296
    }
}

type Leaf = {path: string, gen: (rng: () => number) => number | boolean}

// Walk decoded data alongside its schema, yielding bounded scalar (integer/boolean) leaf fields with
// a generator that produces a fresh in-range value. Enum/const (discriminator) fields, arrays,
// variable strings and the structural fields above are skipped.
function* leaves(data: any, schema: any, prefix: string): Generator<Leaf> {
    if (!schema || !schema.properties || data == null || typeof data !== 'object') return
    for (const key of Object.keys(schema.properties)) {
        if (!(key in data)) continue
        const node: any = schema.properties[key]
        const value: unknown = data[key]
        const path: string = prefix ? `${prefix}.${key}` : key
        if (node.properties && value && typeof value === 'object' && !Array.isArray(value)) {
            yield* leaves(value, node, path)
            continue
        }
        if (STRUCTURAL_FIELDS.has(key)) continue
        if ((node.type === 'integer' || node.type === 'number') && typeof node.maximum === 'number' && typeof value === 'number' && !node.enum) {
            const min: number = typeof node.minimum === 'number' ? node.minimum : 0
            const max: number = node.maximum
            yield {path: path, gen: (rng: () => number): number => Math.floor(rng() * (max - min + 1)) + min}
        } else if (node.type === 'boolean' && typeof value === 'boolean') {
            yield {path: path, gen: (rng: () => number): boolean => rng() < 0.5}
        }
    }
}

function setPath(obj: any, path: string, value: number | boolean): void {
    const keys: string[] = path.split('.')
    let cursor: any = obj
    for (let i: number = 0; i < keys.length - 1; i++) cursor = cursor[keys[i]]
    cursor[keys[keys.length - 1]] = value
}

// Structure signature: layer ids + the key/array shape of each layer's data, ignoring values. Used
// to detect structural mutations (which change what decode produces) and skip them as legitimate.
function keyShape(value: unknown): string {
    if (value === null || typeof value !== 'object') return 'v'
    if (Array.isArray(value)) return `[${value.map(keyShape).join(',')}]`
    return `{${Object.keys(value).sort().map((k: string): string => `${k}:${keyShape((value as any)[k])}`).join(',')}}`
}
function shapeSignature(decoded: CodecDecodeResult[]): string {
    return decoded.map((layer: CodecDecodeResult): string => `${layer.id}:${keyShape(layer.data)}`).join('|')
}

test('metamorphic: a fresh valid value in any scalar field keeps decode/encode a fixed point', async (): Promise<void> => {
    const rng: () => number = mulberry32(0xC0FFEE)
    let compared: number = 0
    const failures: string[] = []
    for (const name of AllPacketFixtureNames()) {
        const base: CodecDecodeResult[] = await codec.decode(LoadPacket(name).buffer)
        const baseShape: string = shapeSignature(base)
        for (let i: number = 0; i < base.length; i++) {
            const schema: any = SCHEMAS[base[i].id]
            if (!schema) continue
            for (const leaf of leaves(base[i].data, schema, '')) {
                const mutated: CodecDecodeResult[] = JSON.parse(JSON.stringify(base))
                setPath(mutated[i].data, leaf.path, leaf.gen(rng))
                let encoded: CodecEncodeResult
                try {
                    encoded = await codec.encode(mutated)
                } catch (e) {
                    continue // schema validation refused the value; not an asymmetry
                }
                const redecoded: CodecDecodeResult[] = await codec.decode(encoded.packet)
                if (shapeSignature(redecoded) !== baseShape) continue // structural mutation — legitimate
                const reencoded: CodecEncodeResult = await codec.encode(redecoded)
                compared++
                if (encoded.packet.toString('hex') !== reencoded.packet.toString('hex')) {
                    failures.push(`${name} · ${base[i].id}.${leaf.path}`)
                }
            }
        }
    }
    assert.ok(compared > 200, `expected many value-field checks, only ran ${compared}`)
    assert.deepStrictEqual(failures, [], `decode/encode asymmetry (not a fixed point) on value field(s):\n  ${failures.join('\n  ')}`)
})
