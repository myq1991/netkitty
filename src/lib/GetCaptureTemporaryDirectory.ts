import {existsSync} from 'node:fs'
import {mkdirSync} from 'fs'

/**
 * Get capture temporary cache directory
 * @param tmpDir
 * @constructor
 */
export function GetCaptureTemporaryDirectory(tmpDir: string): string {
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, {recursive: true})
    return tmpDir
}
