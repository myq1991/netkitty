import {Codec, CodecDecodeResult} from '@netkitty/codec'
import {IPcapPacketInfo, PcapParserCore} from '@netkitty/pcap-core'
import {IReadBackend} from '../interfaces/IReadBackend'
import {IWorkerEndpoint} from './IWorkerEndpoint'
import {ColumnarIndexStore} from '../stores/ColumnarIndexStore'
import {FrameIndexer} from '../indexer/FrameIndexer'
import {PcapIndexBuilder} from '../indexer/PcapIndexBuilder'
import {FrameIndexRecord} from '../types/FrameIndexRecord'
import {FrameRow} from '../types/FrameRow'
import {FilterExpression, matchesFilter, matchesIndexed, parseFilter} from '../filter/FilterExpression'

type PendingFrame = {info: IPcapPacketInfo, data: Buffer}

/**
 * Environment-agnostic analysis-worker logic: owns the read backend, columnar index, indexer
 * dictionaries and codec, and wires all request handlers plus watch tailing onto the given endpoint.
 * `makeBackend` adapts the source (node: a path string → NodeFileReadBackend; browser: a Blob →
 * BrowserFileReadBackend). node and browser worker entrypoints each call this with their endpoint and
 * backend factory, so the handler logic lives in one place.
 */
export function installAnalysisHandlers(endpoint: IWorkerEndpoint, makeBackend: (source: unknown) => IReadBackend): void {
    const store: ColumnarIndexStore = new ColumnarIndexStore()
    const indexer: FrameIndexer = new FrameIndexer(store)
    const codec: Codec = new Codec()
    let backend: IReadBackend | null = null

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

    async function materializeFrame(index: number, needs?: string[]): Promise<unknown | null> {
        const record: FrameIndexRecord | null = store.get(index)
        if (!record || !backend) return null
        const bytes: Uint8Array = await backend.read(record.fileOffset, record.capturedLength)
        const layers: CodecDecodeResult[] = await codec.decode(Buffer.from(bytes))
        //JSON round-trip strips the FlexibleObject proxy / closures so the layer tree is structured-cloneable.
        const plain: CodecDecodeResult[] = JSON.parse(JSON.stringify(layers))
        //Projection: a reducer that declares `needs` only receives those layers, cutting cross-thread bytes.
        const projected: CodecDecodeResult[] = needs ? plain.filter((layer: CodecDecodeResult): boolean => needs.includes(layer.id)) : plain
        return {...frameRow(record), capturedLength: record.capturedLength, layers: projected}
    }

    endpoint.handle('open', async (payload: unknown): Promise<{frameCount: number}> => {
        const {source}: {source: unknown} = payload as {source: unknown}
        backend = makeBackend(source)
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

    //Display filter with a column pre-filter: decide each frame from the index columns (conversation
    //key + top protocol) first, and only re-decode the frames a predicate can't settle from columns
    //(direction-sensitive fields, deeper protocols). Common filters (ip.addr / tcp.port / tcp|udp|arp)
    //are answered entirely from the index — no decode.
    endpoint.handle('filter', async (payload: unknown): Promise<number[]> => {
        const {displayFilter}: {displayFilter: string} = payload as {displayFilter: string}
        const expression: FilterExpression = parseFilter(displayFilter)
        const matches: number[] = []
        if (!backend) return matches
        const first: number = store.firstIndex()
        const end: number = first + store.count()
        for (let index: number = first; index < end; index++) {
            const record: FrameIndexRecord | null = store.get(index)
            if (!record) continue
            const conversationKey: string | null = indexer.conversationKey(record.conversationHash)
            const topProtocol: string = indexer.protocolName(record.protocolId)
            const decided: boolean | null = matchesIndexed(expression, conversationKey, topProtocol, record.directionForward)
            if (decided === true) {matches.push(index); continue}
            if (decided === false) continue
            const bytes: Uint8Array = await backend.read(record.fileOffset, record.capturedLength)
            const layers: CodecDecodeResult[] = await codec.decode(Buffer.from(bytes))
            if (matchesFilter(layers, expression)) matches.push(index)
        }
        return matches
    })

    endpoint.handle('getFrames', (payload: unknown): FrameRow[] => {
        const {from, to}: {from: number, to: number} = payload as {from: number, to: number}
        return store.range(from, to).map(frameRow)
    })

    endpoint.handle('getFrame', async (payload: unknown): Promise<unknown> => {
        const {index}: {index: number} = payload as {index: number}
        return materializeFrame(index)
    })

    //Batch of materialized frames (with layers, optionally projected to `needs`), for reducer replay.
    //v1 re-decodes each frame; a v2 optimization runs built-in reducers inside the worker over columns.
    endpoint.handle('getFrameBatch', async (payload: unknown): Promise<unknown[]> => {
        const {from, to, needs}: {from: number, to: number, needs?: string[]} = payload as {from: number, to: number, needs?: string[]}
        const out: unknown[] = []
        for (let index: number = from; index < to; index++) {
            const frame: unknown | null = await materializeFrame(index, needs)
            if (frame !== null) out.push(frame)
        }
        return out
    })

    //--- watch (tail) ----------------------------------------------------------------------------
    //Incremental tail: one long-lived parser, pread newly-appended bytes at a tracked position, index
    //each new frame and push it (with layers) as a 'frame' notify for live reducer feeding. maxFrames
    //caps the index via FIFO eviction so watch memory stays bounded.
    let watchParser: PcapParserCore | null = null
    let watchPosition: number = 0
    let watchLastData: Buffer = Buffer.alloc(0)
    let watchPending: PendingFrame[] = []
    let watchMaxFrames: number = Number.POSITIVE_INFINITY
    let pumping: boolean = false
    let pumpAgain: boolean = false
    let watchTimer: ReturnType<typeof setInterval> | null = null

    async function drainWatch(): Promise<void> {
        for (const frame of watchPending) {
            const layers: CodecDecodeResult[] = await codec.decode(frame.data)
            const timestamp: number = frame.info.seconds + frame.info.microseconds / 1_000_000
            const index: number = indexer.add(layers, frame.info.packetOffset, frame.info.packetLength, frame.info.packetLength, timestamp)
            const record: FrameIndexRecord | null = store.get(index)
            if (record) {
                endpoint.notify('frame', {...frameRow(record), capturedLength: record.capturedLength, layers: JSON.parse(JSON.stringify(layers))})
            }
            if (store.count() > watchMaxFrames) store.evictOldest(store.count() - watchMaxFrames)
        }
        watchPending = []
    }

    async function pumpWatch(): Promise<void> {
        if (pumping) {pumpAgain = true; return}
        pumping = true
        do {
            pumpAgain = false
            if (!backend || !watchParser) break
            const size: number = await backend.size()
            while (watchPosition < size) {
                const length: number = Math.min(65536, size - watchPosition)
                const bytes: Uint8Array = await backend.read(watchPosition, length)
                if (bytes.length === 0) break
                watchPosition += bytes.length
                watchParser.write(Buffer.from(bytes))
                await drainWatch()
            }
        } while (pumpAgain)
        pumping = false
    }

    endpoint.handle('watch', async (payload: unknown): Promise<{frameCount: number}> => {
        const {source, maxFrames}: {source: unknown, maxFrames?: number} = payload as {source: unknown, maxFrames?: number}
        backend = makeBackend(source)
        watchMaxFrames = maxFrames !== undefined ? maxFrames : Number.POSITIVE_INFINITY
        watchPosition = 0
        watchPending = []
        watchParser = new PcapParserCore({
            onPacketData: (data: Buffer): void => {watchLastData = data},
            onPacket: (info: IPcapPacketInfo): void => {watchPending.push({info: info, data: watchLastData})}
        })
        await pumpWatch()
        //Active polling rather than fs.watch events: a self-driven timer tails reliably even under load.
        if (watchTimer !== null) clearInterval(watchTimer)
        watchTimer = setInterval((): void => {void pumpWatch()}, 100)
        return {frameCount: store.count()}
    })
}
