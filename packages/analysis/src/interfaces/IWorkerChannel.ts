/**
 * Thin transport seam to the analysis worker: correlated request/response plus fire-and-forget
 * notify, over worker_threads (node) or Web Worker (browser) postMessage. ArrayBuffers in the
 * transfer list move without copying. Only the invoke/notify semantics are borrowed from capture's
 * pipe layer — the transport itself is plain postMessage, not socket-ipc.
 */
export interface IWorkerChannel {
    request<T>(method: string, payload?: unknown, transfer?: ArrayBuffer[]): Promise<T>
    notify(method: string, payload?: unknown, transfer?: ArrayBuffer[]): void
    on(method: string, handler: (payload: unknown) => void): void
    terminate(): void
}
