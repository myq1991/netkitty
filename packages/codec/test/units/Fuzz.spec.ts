import {test} from 'node:test'
import assert from 'node:assert'
import {AllPacketFixtureNames, LoadPacket} from '../lib/Fixtures'
import {codec} from '../lib/RoundTrip'
import {CodecEncodeResult} from '../../src/lib/codec/types/CodecEncodeResult'

/**
 * Deterministic PRNG (mulberry32) so a fuzz failure always reproduces from the fixed seed.
 */
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

/**
 * Corrupt a base packet one of three ways: truncate it, flip a handful of bytes, or append
 * random trailing garbage. This targets the buffer-boundary and invalid-value paths that a
 * real capture of a damaged/hostile packet would exercise.
 */
function mutate(rng: () => number, base: Buffer): Buffer {
    const kind: number = Math.floor(rng() * 3)
    if (kind === 0) {
        const n: number = Math.max(1, Math.floor(rng() * base.length))
        return base.subarray(0, n)
    }
    if (kind === 1) {
        const buffer: Buffer = Buffer.from(base)
        const flips: number = 1 + Math.floor(rng() * 8)
        for (let j: number = 0; j < flips; j++) buffer[Math.floor(rng() * buffer.length)] = Math.floor(rng() * 256)
        return buffer
    }
    const extra: Buffer = Buffer.alloc(1 + Math.floor(rng() * 16))
    for (let j: number = 0; j < extra.length; j++) extra[j] = Math.floor(rng() * 256)
    return Buffer.concat([base, extra])
}

// Malformed-input contract, exercised by fuzzing every fixture with truncation / byte-flips /
// trailing garbage from a fixed seed:
//   1. decode must NEVER throw (best-effort + accumulated errors).
//   2. encode may only fast-fail with the documented Ajv shape-validation error
//      (E_CODEC_SCHEMA_VALIDATE) - never a raw crash (buffer bounds, undefined access, ...).
//   3. re-decoding a successfully encoded packet must never throw.
test('fuzz: decode never throws; encode only schema-fast-fails; re-decode never throws', async (): Promise<void> => {
    const names: string[] = AllPacketFixtureNames()
    const rng: () => number = mulberry32(0x9E3779B9)
    const iterations: number = 200
    for (const name of names) {
        const base: Buffer = LoadPacket(name).buffer
        for (let i: number = 0; i < iterations; i++) {
            const mutated: Buffer = mutate(rng, base)
            const decoded: any = await codec.decode(mutated).catch((e: Error): never => {
                throw new assert.AssertionError({message: `decode threw on a mutation of '${name}' (iter ${i}): ${e.message}`})
            })
            let encoded: CodecEncodeResult
            try {
                encoded = await codec.encode(decoded)
            } catch (e) {
                assert.strictEqual((e as any).code, 'E_CODEC_SCHEMA_VALIDATE',
                    `encode threw a non-validation error on '${name}' (iter ${i}): ${(e as Error).message}`)
                continue
            }
            await codec.decode(encoded.packet).catch((e: Error): never => {
                throw new assert.AssertionError({message: `re-decode threw on '${name}' (iter ${i}): ${e.message}`})
            })
        }
    }
})
