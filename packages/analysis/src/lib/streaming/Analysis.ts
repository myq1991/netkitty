import {AnalysisOptions} from './types/AnalysisOptions'
import {AnalysisSource} from './types/AnalysisSource'
import {AnalysisEvents} from './types/AnalysisEvents'
import {Frame} from './types/Frame'
import {FrameRow} from './types/FrameRow'
import {UpdateContext} from './types/UpdateContext'
import {IAnalysisReducer} from './interfaces/IAnalysisReducer'
import {IWorkerChannel} from './interfaces/IWorkerChannel'

//How many frames to pull per replay batch — bounds memory and back-pressures the worker naturally.
const REPLAY_BATCH: number = 512

type AnyListener = (...args: unknown[]) => void

/**
 * Capture-file analysis facade — a programmable Wireshark-style front door over a pcap/pcapng file.
 * Environment-agnostic: it holds no fs/File/codec at runtime, only talks to a worker channel. Heavy
 * work (read → parse → index → decode) lives in a single worker so open() never blocks the caller and
 * close() releases everything by terminating it. The node channel factory is loaded lazily (require)
 * so this module never statically imports worker_threads; a browser build injects its own factory.
 */
export class Analysis {

    readonly #options: AnalysisOptions

    readonly #spawnChannel: () => IWorkerChannel

    #channel: IWorkerChannel | null = null

    #frameCount: number = 0

    readonly #reducers: Set<IAnalysisReducer<unknown>> = new Set<IAnalysisReducer<unknown>>()

    readonly #listeners: Map<string, Set<AnyListener>> = new Map<string, Set<AnyListener>>()

    constructor(options: AnalysisOptions = {}, spawnChannel?: () => IWorkerChannel) {
        this.#options = options
        this.#spawnChannel = spawnChannel !== undefined ? spawnChannel : (): IWorkerChannel => {
            const factory: {spawnNodeAnalysisChannel: () => IWorkerChannel} = require('./worker/spawnNodeAnalysisChannel')
            return factory.spawnNodeAnalysisChannel()
        }
    }

    /** Read a bounded capture: build the frame index, emit 'complete'. Resolves once indexing finishes. */
    public async open(source: AnalysisSource): Promise<void> {
        const path: string = this.#sourcePath(source)
        const channel: IWorkerChannel = this.#start()
        const result: {frameCount: number} = await channel.request<{frameCount: number}>('open', {source: path})
        this.#frameCount = result.frameCount
    }

    /** Tail a capture being written live: index continuously, never emit 'complete'. */
    public watch(source: AnalysisSource): Promise<void> {
        void source
        throw new Error('Analysis.watch not implemented yet')
    }

    /** Terminate the worker and release the index, cache, and parse state in one shot. */
    public async close(): Promise<void> {
        if (this.#channel) {
            this.#channel.terminate()
            this.#channel = null
        }
        this.#frameCount = 0
    }

    public frameCount(): number {
        return this.#frameCount
    }

    /** A single frame with decoded layers (served through the worker's on-demand re-parse). */
    public async getFrame(index: number): Promise<Frame | null> {
        return this.#require().request<Frame | null>('getFrame', {index: index})
    }

    /** A range of lightweight rows (no decoded layers), for list display. Half-open [from, to). */
    public async getFrames(from: number, to: number): Promise<FrameRow[]> {
        return this.#require().request<FrameRow[]>('getFrames', {from: from, to: to})
    }

    /** Evaluate a display filter, returning the matching frame indices. */
    public filter(displayFilter: string): Promise<number[]> {
        void displayFilter
        throw new Error('Analysis.filter not implemented yet')
    }

    /**
     * Attach a reducer and replay every already-indexed frame into it (phase 'replay'), so stats are
     * complete the moment attach resolves — Wireshark-style "open the stats and they're already there".
     * Frames are pulled from the worker in bounded batches. (watch live-feed is added with watch().)
     */
    public async attachReducer(reducer: IAnalysisReducer<unknown>): Promise<void> {
        const channel: IWorkerChannel = this.#require()
        this.#reducers.add(reducer)
        const total: number = this.#frameCount
        for (let from: number = 0; from < total; from += REPLAY_BATCH) {
            const to: number = Math.min(from + REPLAY_BATCH, total)
            const frames: Frame[] = await channel.request<Frame[]>('getFrameBatch', {from: from, to: to})
            for (const frame of frames) {
                const context: UpdateContext = {index: frame.index, total: total, phase: 'replay'}
                reducer.update(frame, context)
            }
        }
    }

    /** Detach a reducer: stop feeding it and drop the internal reference (its state is the caller's). */
    public detachReducer(reducer: IAnalysisReducer<unknown>): void {
        this.#reducers.delete(reducer)
    }

    public on<E extends keyof AnalysisEvents>(event: E, listener: AnalysisEvents[E]): this {
        let set: Set<AnyListener> | undefined = this.#listeners.get(event)
        if (!set) {
            set = new Set<AnyListener>()
            this.#listeners.set(event, set)
        }
        set.add(listener as AnyListener)
        return this
    }

    public off<E extends keyof AnalysisEvents>(event: E, listener: AnalysisEvents[E]): this {
        this.#listeners.get(event)?.delete(listener as AnyListener)
        return this
    }

    #start(): IWorkerChannel {
        const channel: IWorkerChannel = this.#spawnChannel()
        this.#channel = channel
        channel.on('progress', (payload: unknown): void => {
            const p: {frames: number, bytesRead: number, totalBytes: number} = payload as {frames: number, bytesRead: number, totalBytes: number}
            this.#frameCount = p.frames
            this.#emit('progress', p.bytesRead, p.totalBytes)
        })
        channel.on('complete', (payload: unknown): void => {
            const c: {frameCount: number} = payload as {frameCount: number}
            this.#frameCount = c.frameCount
            this.#emit('complete')
        })
        channel.on('error', (payload: unknown): void => {
            this.#emit('error', payload instanceof Error ? payload : new Error(String(payload)))
        })
        return channel
    }

    #require(): IWorkerChannel {
        if (!this.#channel) throw new Error('Analysis has no open source; call open() or watch() first')
        return this.#channel
    }

    #sourcePath(source: AnalysisSource): string {
        if (typeof source === 'string') return source
        throw new Error('Analysis v1 only supports a filesystem path source; buffer/File sources are not yet implemented')
    }

    #emit(event: string, ...args: unknown[]): void {
        const set: Set<AnyListener> | undefined = this.#listeners.get(event)
        if (!set) return
        for (const listener of set) listener(...args)
    }
}
