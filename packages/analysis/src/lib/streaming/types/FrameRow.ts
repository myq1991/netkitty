/**
 * Lightweight per-frame row for list display and batch projection — no decoded layers. Derived from
 * the columnar index, cheap to stream across the worker boundary in bulk.
 */
export type FrameRow = {
    index: number
    timestamp: number
    length: number
    topProtocol: string
    conversationKey: string | null
    info: string
}
