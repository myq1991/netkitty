import {parentPort, MessagePort} from 'node:worker_threads'
import {WorkerEndpoint} from '../../src/worker/WorkerEndpoint'

//Test-support worker: exercises the WorkerEndpoint/NodeWorkerChannel round-trip. Not a spec itself.
const endpoint: WorkerEndpoint = new WorkerEndpoint(parentPort as MessagePort)

endpoint.handle('echo', (payload: unknown): unknown => payload)
endpoint.handle('add', (payload: unknown): number => {
    const {a, b}: {a: number, b: number} = payload as {a: number, b: number}
    return a + b
})
endpoint.handle('boom', (): never => {throw new Error('boom happened')})
endpoint.handle('ping', (): string => {
    endpoint.notify('pong', {when: 42})
    return 'ack'
})
endpoint.handle('never', (): Promise<unknown> => new Promise<unknown>((): void => {}))
