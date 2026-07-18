import xpipe from 'xpipe'
import {tmpdir} from 'node:os'
import path from 'node:path'
import {randomBytes} from 'node:crypto'
import {existsSync} from 'node:fs'
import {mkdirSync} from 'fs'

/**
 * Generate IPC pipe address
 * @param scope
 * @constructor
 */
export function GeneratePipeAddress(): string {
    const pipesDir: string = path.resolve(tmpdir(), 'netkitty-pipes')
    if (!existsSync(pipesDir)) mkdirSync(pipesDir, {recursive: true})
    return xpipe.eq(path.resolve(pipesDir, `netkitty_pipe_${randomBytes(8).toString('hex')}${Date.now().toString(16)}.sock`))
}
