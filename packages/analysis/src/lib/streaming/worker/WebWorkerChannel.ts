import {IWorkerChannel} from '../interfaces/IWorkerChannel'
import {WorkerMessage} from './WorkerMessage'

/** Structural minimum of a DOM Worker — avoids pulling the dom lib (which clashes with node types). */
export interface WebWorkerLike {
    postMessage(message: unknown, transfer?: unknown[]): void
    terminate(): void
    onmessage: ((event: {data: unknown}) => void) | null
    onerror: ((event: unknown) => void) | null
}

type Pending = {resolve: (value: unknown) => void, reject: (error: Error) => void}

/**
 * Browser side of the worker channel over a Web Worker: correlated request/response, fire-and-forget
 * notify, notify handlers for worker→main pushes, terminate rejecting anything in flight. Mirrors
 * NodeWorkerChannel exactly; only the transport (postMessage/onmessage vs worker_threads) differs.
 */
export class WebWorkerChannel implements IWorkerChannel {

    readonly #worker: WebWorkerLike

    #nextId: number = 1

    readonly #pending: Map<number, Pending> = new Map<number, Pending>()

    readonly #handlers: Map<string, (payload: unknown) => void> = new Map<string, (payload: unknown) => void>()

    constructor(worker: WebWorkerLike) {
        this.#worker = worker
        this.#worker.onmessage = (event: {data: unknown}): void => this.#onMessage(event.data as WorkerMessage)
        this.#worker.onerror = (): void => this.#failAll(new Error('web worker error'))
    }

    public request<T>(method: string, payload?: unknown, transfer?: ArrayBuffer[]): Promise<T> {
        const id: number = this.#nextId++
        return new Promise<T>((resolve: (value: T) => void, reject: (error: Error) => void): void => {
            this.#pending.set(id, {resolve: resolve as (value: unknown) => void, reject: reject})
            this.#worker.postMessage({kind: 'request', id: id, method: method, payload: payload}, transfer ? transfer : [])
        })
    }

    public notify(method: string, payload?: unknown, transfer?: ArrayBuffer[]): void {
        this.#worker.postMessage({kind: 'notify', method: method, payload: payload}, transfer ? transfer : [])
    }

    public on(method: string, handler: (payload: unknown) => void): void {
        this.#handlers.set(method, handler)
    }

    public terminate(): void {
        this.#worker.terminate()
        this.#failAll(new Error('worker channel terminated'))
    }

    #onMessage(message: WorkerMessage): void {
        if (message.kind === 'response') {
            const pending: Pending | undefined = this.#pending.get(message.id)
            if (!pending) return
            this.#pending.delete(message.id)
            if (message.ok) pending.resolve(message.payload)
            else pending.reject(new Error(message.error !== undefined ? message.error : 'worker request failed'))
        } else if (message.kind === 'notify') {
            const handler: ((payload: unknown) => void) | undefined = this.#handlers.get(message.method)
            if (handler) handler(message.payload)
        }
    }

    #failAll(error: Error): void {
        for (const pending of this.#pending.values()) pending.reject(error)
        this.#pending.clear()
    }
}
