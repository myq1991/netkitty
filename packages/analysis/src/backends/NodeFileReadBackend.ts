import {open, stat, type FileHandle, type FileReadResult} from 'node:fs/promises'
import {watchFile, unwatchFile, type Stats} from 'node:fs'
import {IReadBackend} from '../interfaces/IReadBackend'

/**
 * node IReadBackend over a filesystem path: positional pread for random single-frame access, a
 * chunked async iterator for sequential index building, and fs.watch for tailing a growing capture.
 * A single FileHandle is opened lazily and reused for size/read/stream; close() releases it.
 */
export class NodeFileReadBackend implements IReadBackend {

    readonly #path: string

    readonly #chunkSize: number

    #handle: FileHandle | null = null

    constructor(path: string, chunkSize: number = 1 << 16) {
        this.#path = path
        this.#chunkSize = chunkSize
    }

    async #fileHandle(): Promise<FileHandle> {
        if (!this.#handle) this.#handle = await open(this.#path, 'r')
        return this.#handle
    }

    public async size(): Promise<number> {
        return (await stat(this.#path)).size
    }

    public async read(offset: number, length: number): Promise<Uint8Array> {
        const handle: FileHandle = await this.#fileHandle()
        const buffer: Buffer = Buffer.allocUnsafe(length)
        const result: FileReadResult<Buffer> = await handle.read(buffer, 0, length, offset)
        return result.bytesRead === length ? buffer : buffer.subarray(0, result.bytesRead)
    }

    public async *createStream(): AsyncIterableIterator<Uint8Array> {
        const handle: FileHandle = await this.#fileHandle()
        let position: number = 0
        while (true) {
            const buffer: Buffer = Buffer.allocUnsafe(this.#chunkSize)
            const result: FileReadResult<Buffer> = await handle.read(buffer, 0, this.#chunkSize, position)
            if (result.bytesRead <= 0) break
            position += result.bytesRead
            yield result.bytesRead === this.#chunkSize ? buffer : buffer.subarray(0, result.bytesRead)
        }
    }

    public watch(onChange: () => void): () => void {
        //stat-polling (watchFile) rather than fs.watch: reliable across platforms for tailing a
        //steadily growing capture, at the cost of a small polling latency.
        const listener: (curr: Stats, prev: Stats) => void = (curr: Stats, prev: Stats): void => {
            if (curr.size !== prev.size || curr.mtimeMs !== prev.mtimeMs) onChange()
        }
        watchFile(this.#path, {interval: 100}, listener)
        return (): void => unwatchFile(this.#path, listener)
    }

    public async close(): Promise<void> {
        if (this.#handle) {
            await this.#handle.close()
            this.#handle = null
        }
    }
}
