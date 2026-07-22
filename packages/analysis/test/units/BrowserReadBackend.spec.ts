import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync} from 'node:fs'
import {Codec, CodecDecodeResult} from '@netkitty/codec'
import {BrowserFileReadBackend} from '../../src/backends/BrowserFileReadBackend'
import {NodeFileReadBackend} from '../../src/backends/NodeFileReadBackend'
import {ColumnarIndexStore} from '../../src/stores/ColumnarIndexStore'
import {FrameIndexer} from '../../src/indexer/FrameIndexer'
import {PcapIndexBuilder} from '../../src/indexer/PcapIndexBuilder'
import {FrameIndexRecord} from '../../src/types/FrameIndexRecord'
import {FixtureCapturePath} from '../lib/Fixtures'

const CAPTURE: string = FixtureCapturePath('iec104.pcap')
const GOLDEN: Buffer = readFileSync(CAPTURE)

//node (>=18) provides the Blob API, so the browser backend's slice/arrayBuffer logic runs here.
function blobBackend(chunkSize?: number): BrowserFileReadBackend {
    return new BrowserFileReadBackend(new Blob([GOLDEN]), chunkSize)
}

test('browser read backend: size and read match the file bytes', async (): Promise<void> => {
    const backend: BrowserFileReadBackend = blobBackend()
    assert.strictEqual(await backend.size(), GOLDEN.length)
    assert.deepStrictEqual(Buffer.from(await backend.read(0, 24)), GOLDEN.subarray(0, 24))
    assert.deepStrictEqual(Buffer.from(await backend.read(100, 40)), GOLDEN.subarray(100, 140))
    const tail: Uint8Array = await backend.read(GOLDEN.length - 5, 100)
    assert.strictEqual(tail.length, 5)
})

test('browser read backend: createStream concatenates back to the whole file', async (): Promise<void> => {
    const chunks: Uint8Array[] = []
    for await (const chunk of blobBackend(64).createStream()) chunks.push(Buffer.from(chunk))
    assert.deepStrictEqual(Buffer.concat(chunks), GOLDEN)
    assert.ok(chunks.length > 1)
})

test('browser read backend: index build matches the node backend frame-for-frame', async (): Promise<void> => {
    const nodeStore: ColumnarIndexStore = new ColumnarIndexStore()
    const nodeIndexer: FrameIndexer = new FrameIndexer(nodeStore)
    const nodeCount: number = await new PcapIndexBuilder(nodeIndexer, new Codec()).build(new NodeFileReadBackend(CAPTURE, 64))

    const webStore: ColumnarIndexStore = new ColumnarIndexStore()
    const webIndexer: FrameIndexer = new FrameIndexer(webStore)
    const webCount: number = await new PcapIndexBuilder(webIndexer, new Codec()).build(blobBackend(64))

    assert.strictEqual(webCount, nodeCount)
    assert.ok(webCount > 0)
    for (let i: number = 0; i < nodeCount; i++) {
        const nodeRecord: FrameIndexRecord = nodeStore.get(i)!
        const webRecord: FrameIndexRecord = webStore.get(i)!
        assert.strictEqual(webRecord.fileOffset, nodeRecord.fileOffset, `frame ${i} offset`)
        assert.strictEqual(webRecord.capturedLength, nodeRecord.capturedLength, `frame ${i} length`)
        assert.strictEqual(webRecord.timestamp, nodeRecord.timestamp, `frame ${i} timestamp`)
        assert.strictEqual(webIndexer.conversationKey(webRecord.conversationHash), nodeIndexer.conversationKey(nodeRecord.conversationHash), `frame ${i} conversation`)
        assert.strictEqual(webIndexer.protocolName(webRecord.protocolId), nodeIndexer.protocolName(nodeRecord.protocolId), `frame ${i} protocol`)
    }
})

test('browser read backend: random read supports on-demand re-decode', async (): Promise<void> => {
    const store: ColumnarIndexStore = new ColumnarIndexStore()
    const indexer: FrameIndexer = new FrameIndexer(store)
    const backend: BrowserFileReadBackend = blobBackend(64)
    await new PcapIndexBuilder(indexer, new Codec()).build(backend)
    const record: FrameIndexRecord = store.get(0)!
    const bytes: Uint8Array = await backend.read(record.fileOffset, record.capturedLength)
    const layers: CodecDecodeResult[] = await new Codec().decode(Buffer.from(bytes))
    assert.ok(layers.length > 0)
    assert.strictEqual(layers[0].id, 'eth')
})
