import {AnalysisOptions} from './types/AnalysisOptions'
import {AnalysisSource} from './types/AnalysisSource'
import {AnalysisEvents} from './types/AnalysisEvents'
import {Frame} from './types/Frame'
import {FrameRow} from './types/FrameRow'
import {IAnalysisReducer} from './interfaces/IAnalysisReducer'

/**
 * Capture-file analysis facade — a programmable Wireshark-style front door over a pcap/pcapng file.
 * Environment-agnostic: it holds no fs/File/codec at runtime, only talks to a worker channel. Heavy
 * work (read → parse → index → decode → built-in reducers) lives in a single worker so open()/watch()
 * never block the caller and close() releases everything by terminating it.
 *
 * v1 skeleton: signatures are frozen here; each method is filled in over the subsequent steps.
 */
export class Analysis {

    readonly #options: AnalysisOptions

    constructor(options: AnalysisOptions = {}) {
        this.#options = options
    }

    /** Read a bounded capture: build the frame index, then emit 'complete'. */
    public open(source: AnalysisSource): Promise<void> {
        throw new Error('Analysis.open not implemented yet')
    }

    /** Tail a capture being written live: index continuously, never emit 'complete'. */
    public watch(source: AnalysisSource): Promise<void> {
        throw new Error('Analysis.watch not implemented yet')
    }

    /** Terminate the worker and release the index, cache, and parse state in one shot. */
    public close(): Promise<void> {
        throw new Error('Analysis.close not implemented yet')
    }

    public frameCount(): number {
        throw new Error('Analysis.frameCount not implemented yet')
    }

    /** A single frame with decoded layers (served through the LRU decode cache). */
    public getFrame(index: number): Promise<Frame | null> {
        throw new Error('Analysis.getFrame not implemented yet')
    }

    /** A range of lightweight rows (no decoded layers), for list display. */
    public getFrames(from: number, to: number): Promise<FrameRow[]> {
        throw new Error('Analysis.getFrames not implemented yet')
    }

    /** Evaluate a display filter, returning the matching frame indices. */
    public filter(displayFilter: string): Promise<number[]> {
        throw new Error('Analysis.filter not implemented yet')
    }

    /** Attach a reducer; it replays every already-indexed frame, then follows the live stream. */
    public attachReducer(reducer: IAnalysisReducer<unknown>): Promise<void> {
        throw new Error('Analysis.attachReducer not implemented yet')
    }

    /** Detach a reducer: stop feeding it and drop the internal reference. */
    public detachReducer(reducer: IAnalysisReducer<unknown>): void {
        throw new Error('Analysis.detachReducer not implemented yet')
    }

    public on<E extends keyof AnalysisEvents>(event: E, listener: AnalysisEvents[E]): this {
        throw new Error('Analysis.on not implemented yet')
    }

    public off<E extends keyof AnalysisEvents>(event: E, listener: AnalysisEvents[E]): this {
        throw new Error('Analysis.off not implemented yet')
    }
}
