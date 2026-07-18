import {parentPort, MessagePort} from 'node:worker_threads'
import {Codec, CodecDecodeResult} from '@netkitty/codec'
import {WorkerEndpoint} from './WorkerEndpoint'
import {NodeFileReadBackend} from '../backends/NodeFileReadBackend'
import {ColumnarIndexStore} from '../stores/ColumnarIndexStore'
import {FrameIndexer} from '../indexer/FrameIndexer'
import {PcapIndexBuilder} from '../indexer/PcapIndexBuilder'
import {FrameIndexRecord} from '../types/FrameIndexRecord'
import {FrameRow} from '../types/FrameRow'

/**
 * The analysis worker: owns the read backend, columnar index, indexer dictionaries and codec. It
 * indexes on 'open' (read → partial-decode → columnar index), answers frame queries by re-reading
 * and decoding on demand, and pushes progress/complete notifications. Killing the worker
 * (channel.terminate) releases all of this in one shot — that is Analysis.close().
 */
const endpoint: WorkerEndpoint = new WorkerEndpoint(parentPort as MessagePort)
const store: ColumnarIndexStore = new ColumnarIndexStore()
const indexer: FrameIndexer = new FrameIndexer(store)
const codec: Codec = new Codec()
let backend: NodeFileReadBackend | null = null

function frameRow(record: FrameIndexRecord): FrameRow {
    return {
        index: record.index,
        timestamp: record.timestamp,
        length: record.capturedLength,
        topProtocol: indexer.protocolName(record.protocolId),
        conversationKey: indexer.conversationKey(record.conversationHash),
        info: ''
    }
}

endpoint.handle('open', async (payload: unknown): Promise<{frameCount: number}> => {
    const {source}: {source: string} = payload as {source: string}
    backend = new NodeFileReadBackend(source)
    const builder: PcapIndexBuilder = new PcapIndexBuilder(indexer, codec)
    const frameCount: number = await builder.build(backend, {
        onProgress: (bytesRead: number, totalBytes: number): void => {
            endpoint.notify('progress', {frames: store.count(), bytesRead: bytesRead, totalBytes: totalBytes})
        }
    })
    endpoint.notify('complete', {frameCount: frameCount})
    return {frameCount: frameCount}
})

endpoint.handle('frameCount', (): number => store.count())

endpoint.handle('getFrames', (payload: unknown): FrameRow[] => {
    const {from, to}: {from: number, to: number} = payload as {from: number, to: number}
    return store.range(from, to).map(frameRow)
})

endpoint.handle('getFrame', async (payload: unknown): Promise<unknown> => {
    const {index}: {index: number} = payload as {index: number}
    const record: FrameIndexRecord | null = store.get(index)
    if (!record || !backend) return null
    const bytes: Uint8Array = await backend.read(record.fileOffset, record.capturedLength)
    const layers: CodecDecodeResult[] = await codec.decode(Buffer.from(bytes))
    //JSON round-trip strips the FlexibleObject proxy / closures so the layer tree is structured-cloneable.
    return {...frameRow(record), capturedLength: record.capturedLength, layers: JSON.parse(JSON.stringify(layers))}
})
