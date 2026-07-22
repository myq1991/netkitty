/** Construction-time knobs for an Analysis instance. */
export type AnalysisOptions = {
    //LRU decode-cache ceiling in bytes; defaults to an internal ~64MB.
    parseCacheBytes?: number
    //Optional index frame ceiling (mainly for watch tails): FIFO-evict the oldest past it. Default: unbounded.
    maxFrames?: number
}
