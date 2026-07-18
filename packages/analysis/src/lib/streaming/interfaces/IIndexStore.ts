import {FrameIndexRecord} from '../types/FrameIndexRecord'

/**
 * Append-only frame index with random access, range slicing, predicate scan, and FIFO eviction. The
 * v1 implementation is columnar TypedArray (heap-external, shared by node and browser); a SQLite
 * backend is a v2 seam for when the index outgrows memory or needs persistence.
 */
export interface IIndexStore {
    append(record: FrameIndexRecord): number
    get(index: number): FrameIndexRecord | null
    range(from: number, to: number): FrameIndexRecord[]
    scan(predicate: (record: FrameIndexRecord) => boolean): number[]
    count(): number
    //Drop the oldest `count` frames (watch FIFO governance).
    evictOldest(count: number): void
    clear(): void
}
