import {WebWorkerEndpoint, WorkerScopeLike} from './WebWorkerEndpoint'
import {BrowserFileReadBackend} from '../backends/BrowserFileReadBackend'
import {IReadBackend} from '../interfaces/IReadBackend'
import {installAnalysisHandlers} from './AnalysisWorkerCore'

/**
 * Browser analysis worker entrypoint: a WebWorkerEndpoint over the worker global scope, and a backend
 * factory that treats the source as a Blob/ArrayBuffer/Uint8Array. All handler logic lives in
 * AnalysisWorkerCore. Bundled (esbuild + Buffer polyfill) into a Web Worker script; never loaded in node.
 */
declare const self: WorkerScopeLike

installAnalysisHandlers(
    new WebWorkerEndpoint(self),
    (source: unknown): IReadBackend => {
        if (source instanceof ArrayBuffer) return new BrowserFileReadBackend(new Blob([source]))
        if (source instanceof Uint8Array) return new BrowserFileReadBackend(new Blob([source]))
        return new BrowserFileReadBackend(source as Blob)
    }
)
