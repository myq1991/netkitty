import path from 'node:path'
import {tmpdir} from 'node:os'
import {existsSync} from 'node:fs'
import {mkdirSync} from 'fs'

let cacheDir: string

/**
 * Get capture temporary cache directory
 * @constructor
 */
export function GetCaptureTemporaryDirectory(): string {
    if (cacheDir) return cacheDir
    cacheDir = path.resolve(tmpdir(), 'netkitty-tmp')
    if (!existsSync(cacheDir)) mkdirSync(cacheDir, {recursive: true})
    return cacheDir
}
