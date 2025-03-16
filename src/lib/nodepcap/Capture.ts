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
import {IWrotePacketInfo} from '../pcap/PcapWriter'

export class Capture extends EventEmitter {

    protected readonly workerModule: string = path.resolve(__dirname, './workers/CaptureWorker.js')

    protected readonly device: string

    protected readonly temporaryFilename: string

    protected readonly pipeServer: PipeServer

    protected readonly bypassFilesystem: boolean = false

    protected hasWorker: boolean = false

    protected worker: ChildProcess | UtilityProcess | undefined

    protected workerId: string | undefined

    protected workerSocket: PipeClientSocket | undefined

    protected workerDestroying: boolean = false

    protected started: boolean = false

    protected paused: boolean = false

    protected operating: boolean = false

    #filter: string = ''

    public get filter(): string {
        return this.#filter
    }

    /**
     * Constructor
     * @param options
     */
    constructor(options: ICaptureOptions) {
        super()
        this.workerModule = options.workerModule ? options.workerModule : this.workerModule
        this.device = options.device
        this.#filter = options.filter ? options.filter : ''
        if (!options.workerModule) {
            //Use origin worker module, check capture device is available
            if (!GetNetworkInterfaces().filter((availableDevice: INetworkInterface): boolean => availableDevice.name === this.device).length) throw new DeviceNotFoundError(`Device ${this.device} not found`)
        }
        this.bypassFilesystem = !!options.bypassFilesystem
        this.temporaryFilename = GetDeviceCaptureTemporaryFilename(this.device)
        this.pipeServer = new PipeServer()
    }

    /**
     * Create and initialize capture worker
     * @protected
     */
    protected createCaptureWorker(): void {
        this.hasWorker = true
        this.workerId = `CW_${Date.now().toString(16)}${randomInt(32).toString(16)}`
        const env: Record<string, string> = {
            captureWorkerId: this.workerId,
            captureDevice: this.device,
            captureFilter: this.#filter,
            captureTemporaryFilename: this.temporaryFilename,
            bypassFilesystem: String(this.bypassFilesystem),
            socketPath: this.pipeServer.socketPath
        }
        this.getWorkerSocket().then((clientSocket: PipeClientSocket): void => {
            clientSocket.on('packet', (wrotePacketInfo: IWrotePacketInfo): void => {
                this.emit('rawPacket', wrotePacketInfo.packet, wrotePacketInfo.seconds, wrotePacketInfo.microseconds)
                this.emit('packet', wrotePacketInfo)
            })
        })
        this.worker = isElectron() ? utilityProcess.fork(this.workerModule, [], {env: env}) : childProcess.fork(this.workerModule, [], {env: env})
    }

    /**
     * Destroy capture worker
     * @protected
     */
    protected async destroyCaptureWorker(): Promise<void> {
        if (!this.hasWorker) return
        if (this.workerDestroying) {
            while (this.workerDestroying) await new Promise(resolve => setTimeout(resolve, 10))
            return
        }
        this.workerDestroying = true
        await new Promise<void>(resolve => {
            if (this.workerSocket && this.worker) {
                const disconnectHandler: () => void = (): void => {
                    clearTimeout(notifyExitTimeout)
                    return resolve()
                }
                this.workerSocket.once('disconnect', disconnectHandler)
                this.workerSocket.notify('exit')
                const notifyExitTimeout: NodeJS.Timeout = setTimeout((): void => {
                    this.workerSocket?.off('disconnect', disconnectHandler)
                    this.worker?.kill('SIGINT')
                    return resolve()
                }, 10000)
            }
        })
        this.workerSocket = undefined
        this.worker = undefined
        this.workerId = undefined
        this.workerDestroying = false
        this.hasWorker = false
    }

    /**
     * Get worker socket
     * @protected
     */
    protected async getWorkerSocket(): Promise<PipeClientSocket> {
        return new Promise(resolve => {
            if (!this.workerSocket) {
                this.pipeServer.once('connect', (clientSocket: PipeClientSocket): void => {
                    this.workerSocket = clientSocket
                    return resolve(this.workerSocket)
                })
            } else {
                return resolve(this.workerSocket)
            }
        })
    }

    /**
     * Clean resources before start capture
     * @protected
     */
    protected async cleanResources(): Promise<void> {
        //Clean cached capture data
        if (existsSync(this.temporaryFilename)) await rm(this.temporaryFilename, {recursive: true, force: true})
        //Clean old worker resources
        if (this.worker && this.workerSocket) await this.destroyCaptureWorker()
    }

    /**
     * Wait other operation done
     * @protected
     */
    protected async waitOperationDone(): Promise<void> {
        while (this.operating) await new Promise(resolve => setTimeout(resolve, 10))
    }

    /**
     * Start capture packets
     */
    public async start(): Promise<void> {
        if (this.paused) return await this.resume()
        if (this.started) return
        await this.waitOperationDone()
        this.operating = true
        try {
            this.started = true
            await this.cleanResources()
            this.createCaptureWorker()
            const workerSocket: PipeClientSocket = await this.getWorkerSocket()
            await workerSocket.invoke('start')
        } catch (e) {
            this.started = false
        }
        this.operating = false
    }

    /**
     * Stop capture packets
     */
    public async stop(): Promise<void> {
        if (!this.started) return
        if (this.workerDestroying) return
        await this.waitOperationDone()
        this.operating = true
        const workerSocket: PipeClientSocket = await this.getWorkerSocket()
        await workerSocket.invoke('stop')
        await this.destroyCaptureWorker()
        this.started = false
        this.operating = false
    }

    /**
     * Pause capture packets
     */
    public async pause(): Promise<void> {
        if (!this.started) return
        if (this.hasWorker) return
        if (this.workerDestroying) return
        await this.waitOperationDone()
        this.operating = true
        const workerSocket: PipeClientSocket = await this.getWorkerSocket()
        await workerSocket.invoke('stop')
        this.paused = true
        this.operating = false
    }

    /**
     * Resume capture packets
     */
    public async resume(): Promise<void> {
        if (!this.started) return
        if (this.hasWorker) return
        if (this.workerDestroying) return
        await this.waitOperationDone()
        this.operating = true
        const workerSocket: PipeClientSocket = await this.getWorkerSocket()
        await workerSocket.invoke('start')
        this.paused = false
        this.operating = false
    }

    /**
     * Set capture filter
     * @param filter
     */
    public async setFilter(filter: string): Promise<void> {
        if (!this.started) return
        if (this.hasWorker) return
        if (this.workerDestroying) return
        await this.waitOperationDone()
        this.operating = true
        const workerSocket: PipeClientSocket = await this.getWorkerSocket()
        await workerSocket.invoke('setFilter', filter)
        this.#filter = filter
        this.operating = false
    }
}
