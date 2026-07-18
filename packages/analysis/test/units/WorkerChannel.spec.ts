import {test} from 'node:test'
import assert from 'node:assert'
import {Worker} from 'node:worker_threads'
import path from 'node:path'
import {NodeWorkerChannel} from '../../src/lib/streaming/worker/NodeWorkerChannel'

const WORKER_PATH: string = path.resolve(__dirname, '../lib/echoWorker.js')

function spawn(): {channel: NodeWorkerChannel, worker: Worker} {
    const worker: Worker = new Worker(WORKER_PATH)
    return {channel: new NodeWorkerChannel(worker), worker: worker}
}

test('worker channel: request returns the handler result across the thread boundary', async (): Promise<void> => {
    const {channel, worker}: {channel: NodeWorkerChannel, worker: Worker} = spawn()
    assert.deepStrictEqual(await channel.request('echo', {hello: 'world'}), {hello: 'world'})
    assert.strictEqual(await channel.request('add', {a: 3, b: 4}), 7)
    channel.terminate()
    await new Promise<void>((resolve: () => void): void => {worker.on('exit', (): void => resolve())})
})

test('worker channel: a throwing handler rejects the request with its message', async (): Promise<void> => {
    const {channel, worker}: {channel: NodeWorkerChannel, worker: Worker} = spawn()
    await assert.rejects(channel.request('boom'), /boom happened/)
    channel.terminate()
    await new Promise<void>((resolve: () => void): void => {worker.on('exit', (): void => resolve())})
})

test('worker channel: an unknown method rejects', async (): Promise<void> => {
    const {channel, worker}: {channel: NodeWorkerChannel, worker: Worker} = spawn()
    await assert.rejects(channel.request('does-not-exist'), /no handler/)
    channel.terminate()
    await new Promise<void>((resolve: () => void): void => {worker.on('exit', (): void => resolve())})
})

test('worker channel: on() receives a worker→main notify', async (): Promise<void> => {
    const {channel, worker}: {channel: NodeWorkerChannel, worker: Worker} = spawn()
    const pong: Promise<unknown> = new Promise<unknown>((resolve: (value: unknown) => void): void => {
        channel.on('pong', (payload: unknown): void => resolve(payload))
    })
    assert.strictEqual(await channel.request('ping'), 'ack')
    assert.deepStrictEqual(await pong, {when: 42})
    channel.terminate()
    await new Promise<void>((resolve: () => void): void => {worker.on('exit', (): void => resolve())})
})

test('worker channel: terminate rejects in-flight requests and stops the worker', async (): Promise<void> => {
    const {channel, worker}: {channel: NodeWorkerChannel, worker: Worker} = spawn()
    const exited: Promise<void> = new Promise<void>((resolve: () => void): void => {worker.on('exit', (): void => resolve())})
    const inflight: Promise<unknown> = channel.request('never')
    channel.terminate()
    await assert.rejects(inflight, /terminated/)
    await exited
})
