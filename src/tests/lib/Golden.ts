import {readFileSync, writeFileSync, mkdirSync, existsSync} from 'node:fs'
import path from 'node:path'
import {CodecDecodeResult} from '../../lib/codec/types/CodecDecodeResult'

/**
 * Golden decode-tree snapshots. Byte round-trip only proves decode and encode are mutual inverses;
 * it cannot pin what a field actually decodes to. A golden freezes the full {id,data,errors} tree
 * so any refactor that silently changes a decoded value fails loudly. Each golden is validated once
 * (core fields against the tshark oracle, whole packet against byte round-trip) and then frozen.
 */

const GOLDEN_ROOT: string = path.resolve(__dirname, '../../../src/tests/fixtures/goldens')

export type GoldenLayer = {id: string, data: unknown, errors: unknown}

/** Project a decode result down to the semantically meaningful, serializable snapshot. */
export function toGolden(decoded: CodecDecodeResult[]): GoldenLayer[] {
    return decoded.map((layer: CodecDecodeResult): GoldenLayer => ({id: layer.id, data: layer.data, errors: layer.errors}))
}

export function goldenFile(name: string): string {
    return path.resolve(GOLDEN_ROOT, `${name}.json`)
}

export function goldenExists(name: string): boolean {
    return existsSync(goldenFile(name))
}

export function loadGolden(name: string): GoldenLayer[] {
    return JSON.parse(readFileSync(goldenFile(name), 'utf-8'))
}

export function writeGolden(name: string, golden: GoldenLayer[]): void {
    const file: string = goldenFile(name)
    mkdirSync(path.dirname(file), {recursive: true})
    writeFileSync(file, `${JSON.stringify(golden, null, 2)}\n`)
}
