import {Codec, CodecDecodeResult} from '@netkitty/codec'
import {IPcapPacketInfo, PcapParserCore} from '@netkitty/pcap-core'
import {IReadBackend} from '../interfaces/IReadBackend'
import {FrameIndexer} from './FrameIndexer'

/** Callbacks fired while building the index, for progress reporting and per-frame notification. */
export type IndexBuildHooks = {
    onFrame?: (index: number, info: IPcapPacketInfo) => void
    onProgress?: (bytesRead: number, totalBytes: number) => void
}

type PendingFrame = {info: IPcapPacketInfo, data: Buffer}

/**
 * Drives the index build: pulls bytes from an IReadBackend stream, feeds PcapParserCore, and for each
 * emitted frame runs codec.decode to extract the n-tuple and append a columnar record via FrameIndexer.
 * Frames produced by one chunk are drained (decoded + indexed) before the next chunk is read, so memory
 * stays bounded to one chunk's worth of frames and the async decode naturally back-pressures the reader.
 */
export class PcapIndexBuilder {

    readonly #indexer: FrameIndexer

    readonly #codec: Codec

    constructor(indexer: FrameIndexer, codec: Codec) {
        this.#indexer = indexer
        this.#codec = codec
    }

    public async build(backend: IReadBackend, hooks: IndexBuildHooks = {}): Promise<number> {
        const total: number = await backend.size()
        let bytesRead: number = 0
        let count: number = 0
        const pending: PendingFrame[] = []
        let lastData: Buffer = Buffer.alloc(0)
        const parser: PcapParserCore = new PcapParserCore({
            onPacketData: (data: Buffer): void => {lastData = data},
            onPacket: (info: IPcapPacketInfo): void => {pending.push({info: info, data: lastData})}
        })
        const drain: () => Promise<void> = async (): Promise<void> => {
            for (const frame of pending) {
                const layers: CodecDecodeResult[] = await this.#codec.decode(frame.data)
                const timestamp: number = frame.info.seconds + frame.info.microseconds / 1_000_000
                const index: number = this.#indexer.add(layers, frame.info.packetOffset, frame.info.packetLength, frame.info.packetLength, timestamp)
                if (hooks.onFrame) hooks.onFrame(index, frame.info)
                count++
            }
            pending.length = 0
        }
        for await (const chunk of backend.createStream()) {
            const buffer: Buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
            parser.write(buffer)
            await drain()
            bytesRead += buffer.length
            if (hooks.onProgress) hooks.onProgress(bytesRead, total)
        }
        parser.end()
        await drain()
        return count
    }
}
