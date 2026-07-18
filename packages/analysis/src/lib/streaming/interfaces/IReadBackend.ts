/**
 * Byte-I/O seam over a capture source. The only place node (FileHandle pread / fs.watch) and browser
 * (File.slice / OPFS) diverge; everything above consumes bytes environment-agnostically.
 */
export interface IReadBackend {
    size(): Promise<number>
    //Random access, for on-demand re-parsing of a single frame.
    read(offset: number, length: number): Promise<Uint8Array>
    //Sequential streaming, for building the index.
    createStream(): AsyncIterable<Uint8Array>
    //Tail a growing file; returns an unsubscribe function. Absent when the source can't be watched.
    watch?(onChange: () => void): () => void
}
