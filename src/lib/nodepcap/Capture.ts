import {GetNetworkInterfaces} from './lib/GetNetworkInterfaces'
import {INetworkInterface} from './interfaces/INetworkInterface'
import {ICaptureOptions} from './interfaces/ICaptureOptions'
import {existsSync, rmSync} from 'node:fs'
import {GetDeviceCaptureTemporaryFilename} from '../GetDeviceCaptureTemporaryFilename'
import {createServer} from 'node:net'
import {GeneratePipeAddress} from '../GeneratePipeAddress'

export class Capture {

    protected readonly device: string

    protected readonly cacheFilename: string

    protected filter: string = ''

    /**
     * Get available network devices
     */
    public static get availableDevices(): INetworkInterface[] {
        return GetNetworkInterfaces()
    }

    /**
     * Constructor
     * @param options
     */
    constructor(options: ICaptureOptions) {
        this.device = options.device
        this.filter = options.filter ? options.filter : ''
        if (!Capture.availableDevices.filter((availableDevice: INetworkInterface): boolean => availableDevice.name === this.device).length) throw new Error(`Device ${this.device} not found`)
        this.cacheFilename = GetDeviceCaptureTemporaryFilename(this.device)
        // const server1 = createServer((socket) => {
        //
        // })
        // const sockPath: string = GeneratePipeAddress()
        // console.log('sockPath:', sockPath)
        // server1.listen(sockPath)
    }

    /**
     * Clean cache data
     * @protected
     */
    protected cleanCache(): void {
        if (existsSync(this.cacheFilename)) rmSync(this.cacheFilename, {recursive: true, force: true})
    }

    /**
     * Start capture packets
     */
    public async start(): Promise<void> {
        this.cleanCache()
        //TODO
    }

    /**
     * Stop capture packets
     */
    public async stop(): Promise<void> {
        //TODO
    }

    /**
     * Pause capture packets
     */
    public async pause(): Promise<void> {
        //TODO
    }

    /**
     * Resume capture packets
     */
    public async resume(): Promise<void> {
        //TODO
    }

    /**
     * Set capture filter
     */
    public setFilter(filter: string): void {
        //TODO 不确定是否需要，也许可以通过setter和getter完成
    }
}
