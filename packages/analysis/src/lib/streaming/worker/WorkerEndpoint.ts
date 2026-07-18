import {MessagePort} from 'node:worker_threads'
import {WorkerMessage} from './WorkerMessage'

/**
 * Worker side of the channel: registers request handlers (their return value, awaited, becomes the
 * response) and can push notify messages back to the main thread. Shared by the real analysis worker
 * and test workers, so the request/response wiring lives in one place. A thrown/rejected handler is
 * reported as an error response rather than crashing the worker.
 */
export class WorkerEndpoint {

    readonly #port: MessagePort

    readonly #handlers: Map<string, (payload: unknown) => unknown | Promise<unknown>> = new Map<string, (payload: unknown) => unknown | Promise<unknown>>()

    constructor(port: MessagePort) {
        this.#port = port
        this.#port.on('message', (message: WorkerMessage): void => {void this.#onMessage(message)})
    }

    public handle(method: string, handler: (payload: unknown) => unknown | Promise<unknown>): void {
        this.#handlers.set(method, handler)
    }

    public notify(method: string, payload?: unknown, transfer?: ArrayBuffer[]): void {
        this.#port.postMessage({kind: 'notify', method: method, payload: payload}, transfer ? transfer : [])
    }

    async #onMessage(message: WorkerMessage): Promise<void> {
        if (message.kind === 'request') {
            const handler: ((payload: unknown) => unknown | Promise<unknown>) | undefined = this.#handlers.get(message.method)
            if (!handler) {
                this.#port.postMessage({kind: 'response', id: message.id, ok: false, error: `no handler for method: ${message.method}`})
                return
            }
            try {
                const result: unknown = await handler(message.payload)
                this.#port.postMessage({kind: 'response', id: message.id, ok: true, payload: result})
            } catch (error: unknown) {
                this.#port.postMessage({kind: 'response', id: message.id, ok: false, error: error instanceof Error ? error.message : String(error)})
            }
        } else if (message.kind === 'notify') {
            const handler: ((payload: unknown) => unknown | Promise<unknown>) | undefined = this.#handlers.get(message.method)
            if (handler) void handler(message.payload)
        }
    }
}
