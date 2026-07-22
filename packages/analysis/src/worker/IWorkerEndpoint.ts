/**
 * The worker-side transport an analysis worker needs: register request handlers and push notifies.
 * Implemented by WorkerEndpoint (node worker_threads) and WebWorkerEndpoint (browser Web Worker), so
 * the worker handler logic (AnalysisWorkerCore) is written once against this interface.
 */
export interface IWorkerEndpoint {
    handle(method: string, handler: (payload: unknown) => unknown | Promise<unknown>): void
    notify(method: string, payload?: unknown, transfer?: ArrayBuffer[]): void
}
