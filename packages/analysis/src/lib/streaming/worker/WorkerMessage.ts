/**
 * Wire protocol between the Analysis facade (main thread) and the analysis worker. Only the
 * invoke/notify semantics are borrowed from capture's pipe layer; the transport is plain
 * worker_threads / Web Worker postMessage, and ArrayBuffers ride the transfer list without copying.
 */
export type WorkerRequest = {kind: 'request', id: number, method: string, payload: unknown}
export type WorkerResponse = {kind: 'response', id: number, ok: boolean, payload?: unknown, error?: string}
export type WorkerNotify = {kind: 'notify', method: string, payload: unknown}

export type WorkerMessage = WorkerRequest | WorkerResponse | WorkerNotify
