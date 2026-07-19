import {GetNetworkInterfaces} from './GetNetworkInterfaces'
import {INetworkInterface} from './interfaces/INetworkInterface'
import {CaptureEmitMode, ICaptureOptions} from './interfaces/ICaptureOptions'
import {existsSync, rmSync, writeFileSync} from 'node:fs'
import {GetDeviceCaptureTemporaryFilename} from '../GetDeviceCaptureTemporaryFilename'
import path from 'node:path'
import {randomInt} from 'crypto'
import {cp} from 'node:fs/promises'
import EventEmitter from 'events'
import {DeviceNotFoundError} from '../../errors/DeviceNotFoundError'
import {tmpdir} from 'node:os'
import {IPcapPacketInfo, GeneratePCAPHeader} from '@netkitty/pcap'
import {captureHost, ICaptureSessionConfig} from './CaptureHost'

/**
 * A single live capture. Its packets are captured by a shared host process (see CaptureHost) that runs
 * one native thread per capture, so opening many captures costs one process, not one process each. The
 * public API (start/stop/pause/resume/setFilter/saveTo/dispose + packet/rawPacket events) is unchanged.
 */
export class Capture extends EventEmitter {

    readonly #id: string = `CAP_${Date.now().toString(16)}${randomInt(0xffffffff).toString(16)}`

    readonly #device: string

    readonly #tmpDir: string

    readonly #temporaryFilename: string

    readonly #emit: CaptureEmitMode

    #registered: boolean = false

    #started: boolean = false

    #paused: boolean = false

    #operating: boolean = false

    #filter: string = ''

    #count: number = 0

    public get filter(): string {
        return this.#filter
    }

    public get temporaryFilename(): string {
        return this.#temporaryFilename
    }

    public get count(): number {
        return this.#count
    }

    /**
     * Constructor
     * @param options
     */
    constructor(options: ICaptureOptions) {
        super()
        this.#device = options.device
        this.#filter = options.filter ? options.filter : ''
        this.#emit = options.emit ? options.emit : 'full'
        this.#tmpDir = options.tmpDir ? options.tmpDir : path.resolve(tmpdir(), 'netkitty-tmp')
        if (options.workerModule) {
            captureHost.setWorkerModule(options.workerModule)
        } else {
            //Use the built-in host worker: verify the capture device exists.
            if (!GetNetworkInterfaces().filter((availableDevice: INetworkInterface): boolean => availableDevice.name === this.#device).length) throw new DeviceNotFoundError(`Device ${this.#device} not found`)
        }
        this.#temporaryFilename = options.temporaryFilename ? options.temporaryFilename : GetDeviceCaptureTemporaryFilename(this.#device, this.#tmpDir)
        this.cleanTemporaryFile()
        writeFileSync(this.#temporaryFilename, GeneratePCAPHeader())
    }

    #config(): ICaptureSessionConfig {
        return {device: this.#device, filter: this.#filter, emit: this.#emit, temporaryFilename: this.#temporaryFilename}
    }

    async #ensureRegistered(): Promise<void> {
        if (this.#registered) return
        await captureHost.create(
            this.#id,
            this.#config(),
            (info: IPcapPacketInfo): void => this.#onPacket(info),
            (error: Error): void => {
                //`error` throws if unhandled; only surface a host crash when the caller is listening.
                if (this.listenerCount('error') > 0) this.emit('error', error)
            }
        )
        this.#registered = true
    }

    #onPacket(info: IPcapPacketInfo): void {
        //`rawPacket` carries the packet bytes; in `metadata` mode they are absent (kept only in the
        //file), so emit it only when bytes are present. `packet` (metadata) always fires.
        if (info.packet) this.emit('rawPacket', info.index, info.packet, info.seconds, info.microseconds)
        this.emit('packet', info)
        this.#count += 1
    }

    /**
     * Wait other operation done
     * @protected
     */
    protected async waitOperationDone(): Promise<void> {
        while (this.#operating) await new Promise((resolve: (value: unknown) => void): NodeJS.Timeout => setTimeout(resolve, 10))
    }

    /**
     * Wait for the host writer to flush every packet we have seen (bounded so a lost host can't hang us).
     * @protected
     */
    protected async drainCount(): Promise<void> {
        let guard: number = 0
        while (await captureHost.count(this.#id) !== this.#count && guard++ < 500) await new Promise((resolve: (value: unknown) => void): NodeJS.Timeout => setTimeout(resolve, 10))
    }

    /**
     * Start capture packets
     */
    public async start(): Promise<void> {
        if (this.#paused) return await this.resume()
        if (this.#started) return
        await this.waitOperationDone()
        this.#operating = true
        try {
            this.#started = true
            await this.#ensureRegistered()
            await captureHost.start(this.#id)
        } catch (e) {
            this.#started = false
            this.#operating = false
            throw e
        }
        this.#operating = false
    }

    /**
     * Stop capture packets
     */
    public async stop(): Promise<void> {
        if (!this.#started) return
        await this.waitOperationDone()
        this.#operating = true
        await captureHost.stop(this.#id)
        await this.drainCount()
        this.#started = false
        this.#paused = false
        this.#operating = false
    }

    /**
     * Pause capture packets
     */
    public async pause(): Promise<void> {
        if (!this.#started) return
        if (this.#paused) return
        await this.waitOperationDone()
        this.#operating = true
        await captureHost.stop(this.#id)
        await this.drainCount()
        this.#paused = true
        this.#operating = false
    }

    /**
     * Resume capture packets
     */
    public async resume(): Promise<void> {
        if (!this.#started) return
        if (!this.#paused) return
        await this.waitOperationDone()
        this.#operating = true
        await captureHost.start(this.#id)
        this.#paused = false
        this.#operating = false
    }

    /**
     * Set capture filter
     * @param filter
     */
    public async setFilter(filter: string): Promise<void> {
        if (!this.#registered) {
            this.#filter = filter
            return
        }
        await this.waitOperationDone()
        this.#operating = true
        await captureHost.setFilter(this.#id, filter)
        this.#filter = filter
        this.#operating = false
    }

    /**
     * Save captured pcap to destination
     * @param destination
     */
    public async saveTo(destination: string): Promise<void> {
        await cp(this.temporaryFilename, destination)
    }

    /**
     * Dispose capture
     */
    public async dispose(): Promise<void> {
        await this.stop()
        if (this.#registered) {
            await captureHost.destroy(this.#id)
            this.#registered = false
        }
        if (existsSync(this.#temporaryFilename)) this.cleanTemporaryFile()
    }

    /**
     * Clean temporary pcap file
     * @protected
     */
    protected cleanTemporaryFile(): void {
        rmSync(this.#temporaryFilename, {
            recursive: true,
            force: true
        })
    }

    public on(eventName: 'packet', listener: (pcapPacketInfo: IPcapPacketInfo) => void): this
    public on(eventName: 'rawPacket', listener: (index: number, packet: string, seconds: number, microseconds: number) => void): this
    public on(eventName: 'error', listener: (error: Error) => void): this
    public on(eventName: string, listener: (...args: any[]) => void): this {
        super.on(eventName, listener)
        return this
    }

    public once(eventName: 'packet', listener: (pcapPacketInfo: IPcapPacketInfo) => void): this
    public once(eventName: 'rawPacket', listener: (index: number, packet: string, seconds: number, microseconds: number) => void): this
    public once(eventName: 'error', listener: (error: Error) => void): this
    public once(eventName: string, listener: (...args: any[]) => void): this {
        super.once(eventName, listener)
        return this
    }
}
