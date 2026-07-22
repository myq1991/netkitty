import {FrameIndexRecord} from '../types/FrameIndexRecord'
import {IIndexStore} from '../interfaces/IIndexStore'

/**
 * Columnar, heap-external frame index: each fixed-width field is its own growable TypedArray, so a
 * few million frames cost tens of MB rather than a JS object per frame. Frame numbers are global and
 * monotonic (never reused); physical slot = globalIndex - firstIndex. evictOldest shifts the columns
 * down (FIFO) for watch governance. This is the v1 IIndexStore; a SQLite backend is a v2 seam.
 */
export class ColumnarIndexStore implements IIndexStore {

    #capacity: number

    //Number of frames physically retained.
    #length: number = 0

    //Global frame number of physical slot 0 (advances on eviction).
    #base: number = 0

    #fileOffset: Float64Array

    #capturedLength: Uint32Array

    #originalLength: Uint32Array

    #timestamp: Float64Array

    #protocolId: Uint16Array

    #conversationHash: Uint32Array

    #directionForward: Uint8Array

    constructor(initialCapacity: number = 1024) {
        this.#capacity = Math.max(1, initialCapacity)
        this.#fileOffset = new Float64Array(this.#capacity)
        this.#capturedLength = new Uint32Array(this.#capacity)
        this.#originalLength = new Uint32Array(this.#capacity)
        this.#timestamp = new Float64Array(this.#capacity)
        this.#protocolId = new Uint16Array(this.#capacity)
        this.#conversationHash = new Uint32Array(this.#capacity)
        this.#directionForward = new Uint8Array(this.#capacity)
    }

    public append(record: FrameIndexRecord): number {
        if (this.#length >= this.#capacity) this.#grow()
        const slot: number = this.#length
        this.#fileOffset[slot] = record.fileOffset
        this.#capturedLength[slot] = record.capturedLength
        this.#originalLength[slot] = record.originalLength
        this.#timestamp[slot] = record.timestamp
        this.#protocolId[slot] = record.protocolId
        this.#conversationHash[slot] = record.conversationHash
        this.#directionForward[slot] = record.directionForward
        this.#length++
        return this.#base + slot
    }

    public get(index: number): FrameIndexRecord | null {
        const slot: number = index - this.#base
        if (slot < 0 || slot >= this.#length) return null
        return this.#recordAt(slot)
    }

    /** Records whose global frame number is in the half-open range [from, to), clamped to what exists. */
    public range(from: number, to: number): FrameIndexRecord[] {
        const start: number = Math.max(from, this.#base)
        const end: number = Math.min(to, this.#base + this.#length)
        const out: FrameIndexRecord[] = []
        for (let index: number = start; index < end; index++) out.push(this.#recordAt(index - this.#base))
        return out
    }

    public scan(predicate: (record: FrameIndexRecord) => boolean): number[] {
        const out: number[] = []
        for (let slot: number = 0; slot < this.#length; slot++) {
            const record: FrameIndexRecord = this.#recordAt(slot)
            if (predicate(record)) out.push(record.index)
        }
        return out
    }

    public count(): number {
        return this.#length
    }

    public firstIndex(): number {
        return this.#base
    }

    public evictOldest(count: number): void {
        const drop: number = Math.min(count, this.#length)
        if (drop <= 0) return
        const remaining: number = this.#length - drop
        this.#fileOffset.copyWithin(0, drop, this.#length)
        this.#capturedLength.copyWithin(0, drop, this.#length)
        this.#originalLength.copyWithin(0, drop, this.#length)
        this.#timestamp.copyWithin(0, drop, this.#length)
        this.#protocolId.copyWithin(0, drop, this.#length)
        this.#conversationHash.copyWithin(0, drop, this.#length)
        this.#directionForward.copyWithin(0, drop, this.#length)
        this.#length = remaining
        this.#base += drop
    }

    public clear(): void {
        this.#length = 0
        this.#base = 0
    }

    #recordAt(slot: number): FrameIndexRecord {
        return {
            index: this.#base + slot,
            fileOffset: this.#fileOffset[slot],
            capturedLength: this.#capturedLength[slot],
            originalLength: this.#originalLength[slot],
            timestamp: this.#timestamp[slot],
            protocolId: this.#protocolId[slot],
            conversationHash: this.#conversationHash[slot],
            directionForward: this.#directionForward[slot]
        }
    }

    #grow(): void {
        const next: number = this.#capacity * 2
        const fileOffset: Float64Array = new Float64Array(next)
        const capturedLength: Uint32Array = new Uint32Array(next)
        const originalLength: Uint32Array = new Uint32Array(next)
        const timestamp: Float64Array = new Float64Array(next)
        const protocolId: Uint16Array = new Uint16Array(next)
        const conversationHash: Uint32Array = new Uint32Array(next)
        const directionForward: Uint8Array = new Uint8Array(next)
        fileOffset.set(this.#fileOffset)
        capturedLength.set(this.#capturedLength)
        originalLength.set(this.#originalLength)
        timestamp.set(this.#timestamp)
        protocolId.set(this.#protocolId)
        conversationHash.set(this.#conversationHash)
        directionForward.set(this.#directionForward)
        this.#fileOffset = fileOffset
        this.#capturedLength = capturedLength
        this.#originalLength = originalLength
        this.#timestamp = timestamp
        this.#protocolId = protocolId
        this.#conversationHash = conversationHash
        this.#directionForward = directionForward
        this.#capacity = next
    }
}
