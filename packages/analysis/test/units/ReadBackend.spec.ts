import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync, writeFileSync, rmSync, appendFileSync} from 'node:fs'
import {tmpdir} from 'node:os'
import path from 'node:path'
import {NodeFileReadBackend} from '../../src/lib/streaming/backends/NodeFileReadBackend'
import {FixtureCapturePath} from '../lib/Fixtures'

const CAPTURE: string = FixtureCapturePath('iec104.pcap')
const GOLDEN: Buffer = readFileSync(CAPTURE)

test('read backend: size() matches the file size', async (): Promise<void> => {
    const backend: NodeFileReadBackend = new NodeFileReadBackend(CAPTURE)
    assert.strictEqual(await backend.size(), GOLDEN.length)
    await backend.close()
})

test('read backend: read() returns exact bytes at an offset', async (): Promise<void> => {
    const backend: NodeFileReadBackend = new NodeFileReadBackend(CAPTURE)
    const head: Uint8Array = await backend.read(0, 24)
    assert.deepStrictEqual(Buffer.from(head), GOLDEN.subarray(0, 24))
    const mid: Uint8Array = await backend.read(100, 40)
    assert.deepStrictEqual(Buffer.from(mid), GOLDEN.subarray(100, 140))
    await backend.close()
})

test('read backend: read() past EOF is truncated to what remains', async (): Promise<void> => {
    const backend: NodeFileReadBackend = new NodeFileReadBackend(CAPTURE)
    const tail: Uint8Array = await backend.read(GOLDEN.length - 10, 100)
    assert.strictEqual(tail.length, 10)
    assert.deepStrictEqual(Buffer.from(tail), GOLDEN.subarray(GOLDEN.length - 10))
    await backend.close()
})

test('read backend: createStream() concatenates back to the whole file', async (): Promise<void> => {
    const backend: NodeFileReadBackend = new NodeFileReadBackend(CAPTURE, 64)
    const chunks: Uint8Array[] = []
    for await (const chunk of backend.createStream()) chunks.push(Buffer.from(chunk))
    assert.deepStrictEqual(Buffer.concat(chunks), GOLDEN)
    assert.ok(chunks.length > 1, 'a 64-byte chunk size should yield many chunks')
    await backend.close()
})

test('read backend: watch() fires when the file grows (tail)', async (): Promise<void> => {
    const temp: string = path.join(tmpdir(), `netkitty-readbackend-${process.pid}.bin`)
    writeFileSync(temp, GOLDEN.subarray(0, 100))
    const backend: NodeFileReadBackend = new NodeFileReadBackend(temp)
    let fired: number = 0
    const stop: () => void = backend.watch((): void => {fired++})
    const changed: Promise<void> = new Promise<void>((resolve: () => void): void => {
        const started: number = Date.now()
        const poll: () => void = (): void => {
            if (fired > 0 || Date.now() - started > 3000) return resolve()
            setTimeout(poll, 20)
        }
        poll()
    })
    appendFileSync(temp, GOLDEN.subarray(100, 200))
    await changed
    stop()
    await backend.close()
    rmSync(temp, {force: true})
    assert.ok(fired > 0, 'appending to the watched file should fire onChange')
})
