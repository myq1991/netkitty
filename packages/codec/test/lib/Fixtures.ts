import {readFileSync, readdirSync, statSync} from 'node:fs'
import path from 'node:path'

export type PacketFixture = {
    name: string
    description: string
    source: string
    hex: string
    buffer: Buffer
}

/**
 * Fixtures live in the package's test/fixtures (not compiled by tsc).
 * At runtime this file executes from dist-test/test/lib, and dist-test mirrors
 * the package layout, so the package root is three levels up.
 */
const FIXTURES_ROOT: string = path.resolve(__dirname, '../../../test/fixtures')

/**
 * Load a single-packet hex fixture by name, e.g. LoadPacket('goose/baseline')
 * File format: leading '#' comment lines (description, source), then the hex string
 */
export function LoadPacket(name: string): PacketFixture {
    const filename: string = path.resolve(FIXTURES_ROOT, 'packets', `${name}.hex`)
    const lines: string[] = readFileSync(filename, 'utf-8')
        .split('\n')
        .map((line: string): string => line.trim())
        .filter((line: string): boolean => line.length > 0)
    const comments: string[] = lines
        .filter((line: string): boolean => line.startsWith('#'))
        .map((line: string): string => line.replace(/^#\s*/, ''))
    const hex: string = lines
        .filter((line: string): boolean => !line.startsWith('#'))
        .join('')
        .toLowerCase()
    return {
        name: name,
        description: comments[0] ? comments[0] : '',
        source: comments[1] ? comments[1] : '',
        hex: hex,
        buffer: Buffer.from(hex, 'hex')
    }
}

/**
 * Enumerate every single-packet hex fixture as its LoadPacket name (e.g. 'goose/baseline'),
 * by walking test/fixtures/packets/<dir>/<name>.hex. Used to assert the round-trip
 * invariant across the whole corpus.
 */
export function AllPacketFixtureNames(): string[] {
    const root: string = path.resolve(FIXTURES_ROOT, 'packets')
    const names: string[] = []
    for (const dir of readdirSync(root)) {
        const dirPath: string = path.resolve(root, dir)
        if (!statSync(dirPath).isDirectory()) continue
        for (const file of readdirSync(dirPath)) {
            if (file.endsWith('.hex')) names.push(`${dir}/${file.replace(/\.hex$/, '')}`)
        }
    }
    return names.sort()
}

/**
 * Absolute path of a capture-file fixture, e.g. FixtureCapturePath('tcp-1.pcapng')
 */
export function FixtureCapturePath(name: string): string {
    return path.resolve(FIXTURES_ROOT, 'pcaps', name)
}
