import {test} from 'node:test'
import assert from 'node:assert'
import {WebWorkerChannel, WebWorkerLike} from '../../src/worker/WebWorkerChannel'
import {WebWorkerEndpoint, WorkerScopeLike} from '../../src/worker/WebWorkerEndpoint'

//An in-memory Web Worker pair: main-side (WebWorkerLike) and worker-side (WorkerScopeLike) each
//deliver postMessage to the other's onmessage on a microtask. Exercises the same protocol a real
//Web Worker would, so the channel/endpoint wiring is verified in node (real Chromium is step 10c).
function pair(): {worker: WebWorkerLike, scope: WorkerScopeLike} {
    const worker: WebWorkerLike = {
        onmessage: null,
        onerror: null,
        terminate: (): void => {},
        postMessage: (message: unknown): void => {
            queueMicrotask((): void => {if (scope.onmessage) scope.onmessage({data: message})})
        }
    }
    const scope: WorkerScopeLike = {
        onmessage: null,
        postMessage: (message: unknown): void => {
            queueMicrotask((): void => {if (worker.onmessage) worker.onmessage({data: message})})
        }
    }
    return {worker: worker, scope: scope}
}

function connected(): {channel: WebWorkerChannel, endpoint: WebWorkerEndpoint} {
    const {worker, scope}: {worker: WebWorkerLike, scope: WorkerScopeLike} = pair()
    return {channel: new WebWorkerChannel(worker), endpoint: new WebWorkerEndpoint(scope)}
}

test('web worker channel: request returns the handler result', async (): Promise<void> => {
    const {channel, endpoint}: {channel: WebWorkerChannel, endpoint: WebWorkerEndpoint} = connected()
    endpoint.handle('echo', (payload: unknown): unknown => payload)
    endpoint.handle('add', (payload: unknown): number => {
        const {a, b}: {a: number, b: number} = payload as {a: number, b: number}
        return a + b
    })
    assert.deepStrictEqual(await channel.request('echo', {hello: 'world'}), {hello: 'world'})
    assert.strictEqual(await channel.request('add', {a: 2, b: 5}), 7)
})

test('web worker channel: a throwing handler rejects with its message', async (): Promise<void> => {
    const {channel, endpoint}: {channel: WebWorkerChannel, endpoint: WebWorkerEndpoint} = connected()
    endpoint.handle('boom', (): never => {throw new Error('boom happened')})
    await assert.rejects(channel.request('boom'), /boom happened/)
})

test('web worker channel: an unknown method rejects', async (): Promise<void> => {
    const {channel}: {channel: WebWorkerChannel} = connected()
    await assert.rejects(channel.request('nope'), /no handler/)
})

test('web worker channel: on() receives a worker→main notify', async (): Promise<void> => {
    const {channel, endpoint}: {channel: WebWorkerChannel, endpoint: WebWorkerEndpoint} = connected()
    endpoint.handle('ping', (): string => {endpoint.notify('pong', {when: 7}); return 'ack'})
    const pong: Promise<unknown> = new Promise<unknown>((resolve: (value: unknown) => void): void => {
        channel.on('pong', (payload: unknown): void => resolve(payload))
    })
    assert.strictEqual(await channel.request('ping'), 'ack')
    assert.deepStrictEqual(await pong, {when: 7})
})

test('web worker channel: terminate rejects in-flight requests', async (): Promise<void> => {
    const {channel, endpoint}: {channel: WebWorkerChannel, endpoint: WebWorkerEndpoint} = connected()
    endpoint.handle('never', (): Promise<unknown> => new Promise<unknown>((): void => {}))
    const inflight: Promise<unknown> = channel.request('never')
    channel.terminate()
    await assert.rejects(inflight, /terminated/)
})
