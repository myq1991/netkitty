import EventEmitter from 'events'
import {GetReplayBinding, INativeReplay} from './GetReplayBinding'
import {IReplayOptions} from './interfaces/IReplayOptions'
import {IReplayFrame} from './interfaces/IReplayFrame'
import {IReplayProgress} from './interfaces/IReplayProgress'
import {validateDevice} from './validateDevice'

/**
 * Replays a set of frames to one interface, paced per {@link IReplayOptions}. The whole send loop runs
 * on a dedicated native thread, so the Node event loop is never blocked; progress/done/error arrive as
 * events. Frames are sent verbatim — edit them with the codec before handing them over if needed.
 *
 * ```ts
 * const replay = new Replay({device: 'en0', mode: 'multiplier', rate: 1})
 * replay.addFrames(await loadFrames('capture.pcap'))
 * replay.on('done', (s) => console.log(`sent ${s.sent} frames`))
 * replay.on('error', (e) => console.error(e))
 * replay.start()
 * ```
 */
export class Replay extends EventEmitter {

    readonly #native: INativeReplay

    #started: boolean = false

    #finished: boolean = false

    constructor(options: IReplayOptions) {
        super()
        if (options.validateDevice !== false) validateDevice(options.device)
        const binding: {NetKittyReplay: new (o: Record<string, unknown>) => INativeReplay} = GetReplayBinding()
        this.#native = new binding.NetKittyReplay({
            device: options.device,
            mode: options.mode ?? 'multiplier',
            rate: options.rate ?? 1,
            loop: options.loop ?? 1,
            infinite: options.infinite ?? false,
            loopDelayMs: options.loopDelayMs ?? 0,
            limit: options.limit ?? 0,
            maxSleepMs: options.maxSleepMs ?? 0,
            precision: options.precision ?? 'auto',
            realtime: options.realtime ?? false
        })
    }

    /**
     * Queue frames to send. May be called multiple times before {@link start}; frames are copied into
     * native memory immediately, so the source buffers can be reused afterwards.
     */
    public addFrames(frames: IReplayFrame[]): void {
        this.#native.addFrames(frames.map((f: IReplayFrame): {data: Buffer, seconds: number, nanoseconds: number} => ({
            data: f.data,
            seconds: f.seconds ?? 0,
            nanoseconds: f.nanoseconds ?? 0
        })))
    }

    /**
     * Begin transmitting on the send thread. Idempotent while running. Emits `progress` periodically,
     * then exactly one terminal `done` (with the final totals) or `error`.
     */
    public start(): void {
        if (this.#started) return
        this.#started = true
        this.#finished = false
        this.#native.emit = (event: string, payload: unknown): void => {
            if (event === 'done' || event === 'error') {
                this.#finished = true
                this.#started = false
            }
            this.emit(event, payload)
        }
        this.#native.start()
    }

    /**
     * Ask the send thread to stop as soon as the current frame completes. A `done` event still fires
     * with the totals reached. Safe to call when not running.
     */
    public stop(): void {
        if (!this.#started) return
        this.#native.stop()
        this.#started = false
    }

    /** True while transmitting. */
    public get running(): boolean {
        return this.#started && !this.#finished
    }

    public on(eventName: 'progress', listener: (progress: IReplayProgress) => void): this
    public on(eventName: 'done', listener: (progress: IReplayProgress) => void): this
    public on(eventName: 'error', listener: (error: Error) => void): this
    public on(eventName: string | symbol, listener: (...args: any[]) => void): this {
        return super.on(eventName, listener)
    }

    public once(eventName: 'progress', listener: (progress: IReplayProgress) => void): this
    public once(eventName: 'done', listener: (progress: IReplayProgress) => void): this
    public once(eventName: 'error', listener: (error: Error) => void): this
    public once(eventName: string | symbol, listener: (...args: any[]) => void): this {
        return super.once(eventName, listener)
    }
}
