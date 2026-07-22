import {IReadBackend} from '../interfaces/IReadBackend'

/**
 * Browser IReadBackend over a File/Blob: Blob.slice gives random access (for on-demand re-parsing)
 * and a chunked async iterator (for index building), both via arrayBuffer(). A Blob is immutable, so
 * there is nothing to tail (watch is absent) and no handle to release (close is absent). Works in any
 * environment with the Blob API — node (>=18) included, which is how it is unit-tested.
 */
export class BrowserFileReadBackend implements IReadBackend {

    readonly #blob: Blob

    readonly #chunkSize: number

    constructor(source: Blob, chunkSize: number = 1 << 16) {
        this.#blob = source
        this.#chunkSize = chunkSize
    }

    public async size(): Promise<number> {
        return this.#blob.size
    }

    public async read(offset: number, length: number): Promise<Uint8Array> {
        const slice: Blob = this.#blob.slice(offset, offset + length)
        return new Uint8Array(await slice.arrayBuffer())
    }

    public async *createStream(): AsyncIterableIterator<Uint8Array> {
        let position: number = 0
        while (position < this.#blob.size) {
            const slice: Blob = this.#blob.slice(position, position + this.#chunkSize)
            const bytes: Uint8Array = new Uint8Array(await slice.arrayBuffer())
            if (bytes.length === 0) break
            position += bytes.length
            yield bytes
        }
    }
}
