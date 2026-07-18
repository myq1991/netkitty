/** Construction-time knobs for an Analysis instance. */
export type AnalysisOptions = {
    //LRU decode-cache ceiling in bytes; defaults to an internal ~64MB.
    parseCacheBytes?: number
    //Index frame ceiling for watch() (FIFO eviction past it); open() defaults to unbounded.
    maxFrames?: number
}
