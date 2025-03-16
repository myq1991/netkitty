import {GetNetworkInterfaces} from './lib/GetNetworkInterfaces'
import {INetworkInterface} from './interfaces/INetworkInterface'
import {ICaptureOptions} from './interfaces/ICaptureOptions'
import {existsSync} from 'node:fs'
import {GetDeviceCaptureTemporaryFilename} from '../GetDeviceCaptureTemporaryFilename'
import {ChildProcess} from 'node:child_process'
import path from 'node:path'
import isElectron from 'is-electron'
import * as childProcess from 'child_process'
import {utilityProcess, UtilityProcess} from 'electron'
import {PipeServer} from '../pipe/PipeServer'
import {PipeClientSocket} from '../pipe/PipeClientSocket'
import {randomInt} from 'crypto'
import {rm} from 'node:fs/promises'
import EventEmitter from 'events'
import {DeviceNotFoundError} from '../../errors/DeviceNotFoundError'
import {tmpdir} from 'node:os'
import {IPcapPacketInfo} from '../pcap/interfaces/IPcapPacketInfo'
import {PcapReader} from '../pcap/PcapReader'

export class Capture extends EventEmitter {

    readonly #workerModule: string = path.resolve(__dirname, './workers/CaptureWorker.js')

    readonly #device: string

    readonly #tmpDir: string

    readonly #temporaryFilename: string

    readonly #pipeServer: PipeServer

    #reader: PcapReader | null = null

    #hasWorker: boolean = false

    #worker: ChildProcess | UtilityProcess | undefined

    #workerId: string | undefined

    #workerSocket: PipeClientSocket | undefined

    #workerDestroying: boolean = false

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
        this.#workerModule = options.workerModule ? options.workerModule : this.#workerModule
        this.#device = options.device
        this.#filter = options.filter ? options.filter : ''
        this.#tmpDir = options.tmpDir ? options.tmpDir : path.resolve(tmpdir(), 'netkitty-tmp')
        if (!options.workerModule) {
            //Use origin worker module, check capture device is available
            if (!GetNetworkInterfaces().filter((availableDevice: INetworkInterface): boolean => availableDevice.name === this.#device).length) throw new DeviceNotFoundError(`Device ${this.#device} not found`)
        }
        this.#temporaryFilename = GetDeviceCaptureTemporaryFilename(this.#device, this.#tmpDir)
        this.#pipeServer = new PipeServer()
    }

    /**
     * Create and initialize capture worker
     * @protected
     */
    protected createCaptureWorker(): void {
        this.#hasWorker = true
        this.#workerId = `CW_${Date.now().toString(16)}${randomInt(32).toString(16)}`
        const env: Record<string, string> = {
            captureWorkerId: this.#workerId,
            captureDevice: this.#device,
            captureFilter: this.#filter,
            captureTemporaryFilename: this.#temporaryFilename,
            socketPath: this.#pipeServer.socketPath,
            //Getting packets from pcap reader events, worker does not need to emit events
            doNotEmitPacket: String(true)
        }
        this.getWorkerSocket().then((): void => {
            this.#reader = new PcapReader({filename: this.temporaryFilename, watch: true})
            this.#reader.on('packet', (packetInfo: IPcapPacketInfo): void => {
                this.emit('rawPacket', packetInfo.index, packetInfo.packet, packetInfo.seconds, packetInfo.microseconds)
                this.emit('packet', packetInfo)
            })
        })
        this.#worker = isElectron() ? utilityProcess.fork(this.#workerModule, [], {env: env}) : childProcess.fork(this.#workerModule, [], {env: env})


    }

    /**
     * Destroy capture worker
     * @protected
     */
    protected async destroyCaptureWorker(): Promise<void> {
        if (!this.#hasWorker) return
        if (this.#workerDestroying) {
            while (this.#workerDestroying) await new Promise(resolve => setTimeout(resolve, 10))
            return
        }
        this.#workerDestroying = true
        await new Promise<void>(resolve => {
            if (this.#workerSocket && this.#worker) {
                const disconnectHandler: () => void = (): void => {
                    clearTimeout(notifyExitTimeout)
                    return resolve()
                }
                this.#workerSocket.once('disconnect', disconnectHandler)
                this.#workerSocket.notify('exit')
                const notifyExitTimeout: NodeJS.Timeout = setTimeout((): void => {
                    this.#workerSocket?.off('disconnect', disconnectHandler)
                    this.#worker?.kill('SIGINT')
                    return resolve()
                }, 10000)
            }
        })
        this.#workerSocket = undefined
        this.#worker = undefined
        this.#workerId = undefined
        this.#workerDestroying = false
        this.#hasWorker = false
    }

    /**
     * Get worker socket
     * @protected
     */
    protected async getWorkerSocket(): Promise<PipeClientSocket> {
        return new Promise(resolve => {
            if (!this.#workerSocket) {
                this.#pipeServer.once('connect', (clientSocket: PipeClientSocket): void => {
                    this.#workerSocket = clientSocket
                    return resolve(this.#workerSocket)
                })
            } else {
                return resolve(this.#workerSocket)
            }
        })
    }

    /**
     * Clean resources before start capture
     * @protected
     */
    protected async cleanResources(): Promise<void> {
        //Clean cached capture data
        if (existsSync(this.#temporaryFilename)) await rm(this.#temporaryFilename, {recursive: true, force: true})
        //Clean old worker resources
        if (this.#worker && this.#workerSocket) await this.destroyCaptureWorker()
        await this.#reader?.close()
        this.#reader = null
    }

    /**
     * Wait other operation done
     * @protected
     */
    protected async waitOperationDone(): Promise<void> {
        while (this.#operating) await new Promise(resolve => setTimeout(resolve, 10))
    }

    /**
     * Start capture packets
     */
    public async start(): Promise<PcapReader> {
        if (this.#paused) {
            await this.resume()
            return this.#reader!
        }
        if (this.#started) return this.#reader!
        await this.waitOperationDone()
        this.#operating = true
        try {
            this.#started = true
            await this.cleanResources()
            this.createCaptureWorker()
            const workerSocket: PipeClientSocket = await this.getWorkerSocket()
            await workerSocket.invoke('start')
        } catch (e) {
            this.#started = false
            this.#operating = false
            throw e
        }
        this.#operating = false
        return this.#reader!
    }

    /**
     * Stop capture packets
     */
    public async stop(): Promise<void> {
        if (!this.#started) return
        if (this.#workerDestroying) return
        await this.waitOperationDone()
        this.#operating = true
        const workerSocket: PipeClientSocket = await this.getWorkerSocket()
        await workerSocket.invoke('stop')
        await this.destroyCaptureWorker()
        await this.#reader?.stop()
        this.#started = false
        this.#operating = false
    }

    /**
     * Pause capture packets
     */
    public async pause(): Promise<void> {
        if (!this.#started) return
        if (this.#hasWorker) return
        if (this.#workerDestroying) return
        await this.waitOperationDone()
        this.#operating = true
        const workerSocket: PipeClientSocket = await this.getWorkerSocket()
        await workerSocket.invoke('stop')
        this.#paused = true
        this.#operating = false
    }

    /**
     * Resume capture packets
     */
    public async resume(): Promise<void> {
        if (!this.#started) return
        if (this.#hasWorker) return
        if (this.#workerDestroying) return
        await this.waitOperationDone()
        this.#operating = true
        const workerSocket: PipeClientSocket = await this.getWorkerSocket()
        await workerSocket.invoke('start')
        this.#paused = false
        this.#operating = false
    }

    /**
     * Set capture filter
     * @param filter
     */
    public async setFilter(filter: string): Promise<void> {
        if (!this.#started) return
        if (this.#hasWorker) return
        if (this.#workerDestroying) return
        await this.waitOperationDone()
        this.#operating = true
        const workerSocket: PipeClientSocket = await this.getWorkerSocket()
        await workerSocket.invoke('setFilter', filter)
        this.#filter = filter
        this.#operating = false
    }

    /**
     * Dispose capture
     */
    public async dispose(): Promise<void> {
        await this.stop()
        await this.cleanResources()
    }

    public on(eventName: 'packet', listener: (pcapPacketInfo: IPcapPacketInfo) => void): this
    public on(eventName: 'rawPacket', listener: (index: number, packet: string, seconds: number, microseconds: number) => void): this
    public on(eventName: string, listener: (...args: any[]) => void): this {
        super.on(eventName, listener)
        return this
    }

    public once(eventName: 'packet', listener: (pcapPacketInfo: IPcapPacketInfo) => void): this
    public once(eventName: 'rawPacket', listener: (index: number, packet: string, seconds: number, microseconds: number) => void): this
    public once(eventName: string, listener: (...args: any[]) => void): this {
        super.once(eventName, listener)
        return this
    }
}
