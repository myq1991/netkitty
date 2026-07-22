import {IWorkerEndpoint} from './IWorkerEndpoint'
import {WorkerMessage} from './WorkerMessage'

/** Structural minimum of a Web Worker global scope (self) — avoids pulling the webworker/dom lib. */
export interface WorkerScopeLike {
    onmessage: ((event: {data: unknown}) => void) | null
    postMessage(message: unknown, transfer?: unknown[]): void
}

/**
 * Browser worker side of the channel: registers request handlers (their awaited return becomes the
 * response) and pushes notify messages back to the main thread over the worker global scope. Same
 * request/response wiring as WorkerEndpoint (node), only the transport differs.
 */
export class WebWorkerEndpoint implements IWorkerEndpoint {

    readonly #scope: WorkerScopeLike

    readonly #handlers: Map<string, (payload: unknown) => unknown | Promise<unknown>> = new Map<string, (payload: unknown) => unknown | Promise<unknown>>()

    constructor(scope: WorkerScopeLike) {
        this.#scope = scope
        this.#scope.onmessage = (event: {data: unknown}): void => {void this.#onMessage(event.data as WorkerMessage)}
    }

    public handle(method: string, handler: (payload: unknown) => unknown | Promise<unknown>): void {
        this.#handlers.set(method, handler)
    }

    public notify(method: string, payload?: unknown, transfer?: ArrayBuffer[]): void {
        this.#scope.postMessage({kind: 'notify', method: method, payload: payload}, transfer ? transfer : [])
    }

    async #onMessage(message: WorkerMessage): Promise<void> {
        if (message.kind === 'request') {
            const handler: ((payload: unknown) => unknown | Promise<unknown>) | undefined = this.#handlers.get(message.method)
            if (!handler) {
                this.#scope.postMessage({kind: 'response', id: message.id, ok: false, error: `no handler for method: ${message.method}`})
                return
            }
            try {
                const result: unknown = await handler(message.payload)
                this.#scope.postMessage({kind: 'response', id: message.id, ok: true, payload: result})
            } catch (error: unknown) {
                this.#scope.postMessage({kind: 'response', id: message.id, ok: false, error: error instanceof Error ? error.message : String(error)})
            }
        } else if (message.kind === 'notify') {
            const handler: ((payload: unknown) => unknown | Promise<unknown>) | undefined = this.#handlers.get(message.method)
            if (handler) void handler(message.payload)
        }
    }
}
