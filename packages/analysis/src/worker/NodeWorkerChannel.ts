import {Worker} from 'node:worker_threads'
import {IWorkerChannel} from '../interfaces/IWorkerChannel'
import {WorkerMessage} from './WorkerMessage'

type Pending = {resolve: (value: unknown) => void, reject: (error: Error) => void}

/**
 * Main-thread side of the worker channel over a worker_threads Worker: correlated request/response
 * (a monotonic id maps each reply to its promise), fire-and-forget notify, and notify handlers for
 * worker→main pushes. terminate() kills the worker and rejects anything still in flight — this is how
 * Analysis.close() releases the worker's whole heap in one shot.
 */
export class NodeWorkerChannel implements IWorkerChannel {

    readonly #worker: Worker

    #nextId: number = 1

    readonly #pending: Map<number, Pending> = new Map<number, Pending>()

    readonly #handlers: Map<string, (payload: unknown) => void> = new Map<string, (payload: unknown) => void>()

    constructor(worker: Worker) {
        this.#worker = worker
        this.#worker.on('message', (message: WorkerMessage): void => this.#onMessage(message))
        this.#worker.on('error', (error: Error): void => this.#failAll(error))
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
        void this.#worker.terminate()
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
