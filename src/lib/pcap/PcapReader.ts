import EventEmitter from 'events'
import {FileHandle, open} from 'node:fs/promises'
import {read, ReadStream, WriteStream} from 'node:fs'
import DuplexPair from 'duplexpair'
import {PcapParser} from './lib/PcapParser'
import {IPcapPacketInfo} from './interfaces/IPcapPacketInfo'

export interface IPcapReaderOptions {
    filename: string
    watch?: boolean
    chunkSize?: number
}

export class PcapReader extends EventEmitter {

    protected readonly duplexPair: DuplexPair = new DuplexPair()

    protected readonly filename: string

    protected readonly watch: boolean

    protected readonly chunkSize: number = 64 * 1024

    protected readonly parser: PcapParser

    protected readBufferFileHandle: FileHandle | null

    protected readPacketFileHandle: FileHandle | null

    protected index: number = 0

    protected offset: number = 0

    protected get readBufferFd(): number {
        return this.readBufferFileHandle ? this.readBufferFileHandle.fd : -1
    }

    protected get readPacketFd(): number {
        return this.readPacketFileHandle ? this.readPacketFileHandle.fd : -1
    }

    protected get readStream(): ReadStream {
        return this.duplexPair.socket2
    }

    protected get writeStream(): WriteStream {
        return this.duplexPair.socket1
    }

    constructor(options: IPcapReaderOptions) {
        super()
        this.filename = options.filename
        this.watch = !!options.watch
        this.chunkSize = options.chunkSize ? options.chunkSize : this.chunkSize
        this.parser = PcapParser.parse(this.readStream)
        this.parser.on('packet', (pcapPacketInfo: IPcapPacketInfo): void => {
            this.index = pcapPacketInfo.index
            this.emit('packet', pcapPacketInfo)
        })
        if (this.watch) {
            this.continualRead()
        } else {
            this.straightRead()
        }
    }

    /**
     * Initialize read packet file handle
     * @protected
     */
    protected async initReadPacketFileHandle(): Promise<void> {
        if (!this.readPacketFileHandle) this.readPacketFileHandle = await open(this.filename, 'r')
    }

    /**
     * Initialize read buffer file handle
     * @protected
     */
    protected async initReadBufferFileHandle(): Promise<void> {
        if (!this.readBufferFileHandle) this.readBufferFileHandle = await open(this.filename, 'r')
    }

    /**
     * Read file buffer
     * @protected
     */
    protected async readBuffer(): Promise<boolean> {
        await this.initReadBufferFileHandle()
        return new Promise(resolve => {
            if (this.readBufferFd < 0) return resolve(true)
            read(this.readBufferFd, Buffer.alloc(this.chunkSize), 0, this.chunkSize, this.offset, (err: NodeJS.ErrnoException | null, bytesRead: number, buffer: Buffer): void => {
                let isReachEnd: boolean = false
                if (bytesRead > 0 && !err) {
                    const data: Buffer = Buffer.alloc(bytesRead)
                    buffer.copy(data, 0, 0, bytesRead)
                    this.offset += bytesRead
                    this.writeStream.write(data)
                } else {
                    isReachEnd = true
                }
                return resolve(isReachEnd)
            })
        })
    }

    /**
     * Read file continually
     * @protected
     */
    protected continualRead(): void {
        process.nextTick(async (): Promise<void> => {
            let read: boolean = true
            this.once('stop', (): boolean => read = false)
            let waitUntil: number = 0
            while (read) {
                if (waitUntil && Date.now() >= waitUntil) continue
                waitUntil = 0
                let isReachEnd: boolean = await this.readBuffer()
                if (isReachEnd) waitUntil = Date.now() + 100
            }
            this.emit('done')
        })
    }

    /**
     * Read the file straight
     * @protected
     */
    protected straightRead(): void {
        process.nextTick(async (): Promise<void> => {
            let isReachEnd: boolean = false
            let stopped: boolean = false
            this.once('stop', (): boolean => stopped = true)
            while (!isReachEnd && !stopped) {
                isReachEnd = await this.readBuffer()
            }
            if (!stopped) await this.stop()
            this.emit('done')
        })
    }

    /**
     * Read packet data by record's offset and record's length
     * @param offset
     * @param length
     */
    public async readPacket(offset: number, length: number): Promise<Buffer> {
        await this.initReadPacketFileHandle()
        return await new Promise<Buffer>((resolve, reject) => {
            read(this.readPacketFd, Buffer.alloc(length), 0, length, offset, (err: NodeJS.ErrnoException | null, bytesRead: number, buffer: Buffer): void => {
                if (err) return reject(err)
                if (!bytesRead) return reject(new Error('No data to read'))
                const data: Buffer = Buffer.alloc(length - 16)
                buffer.copy(data, 0, 16, bytesRead)
                return resolve(data)
            })
        })
    }

    /**
     * Stop reading pcap
     */
    public async stop(): Promise<void> {
        await new Promise<void>(resolve => {
            if (this.writeStream.closed) return resolve()
            this.writeStream.once('close', () => resolve())
            this.writeStream.once('error', err => !!err)
            this.writeStream.destroy()
        })
        await new Promise<void>(resolve => {
            if (this.readStream.closed) return resolve()
            this.readStream.once('close', () => resolve())
            this.readStream.once('error', err => !!err)
            this.readStream.destroy()
        })
        await this.readBufferFileHandle?.close()
        this.readBufferFileHandle = null
        this.emit('stop')
    }

    /**
     * Close pcap reader
     */
    public async close(): Promise<void> {
        await this.stop()
        await this.readPacketFileHandle?.close()
        this.readPacketFileHandle = null
        this.emit('close')
    }

    public on(eventName: 'packet', listener: (pcapPacketInfo: IPcapPacketInfo) => void): this
    public on(eventName: 'done', listener: (...args: any[]) => void): this
    public on(eventName: 'stop', listener: (...args: any[]) => void): this
    public on(eventName: 'close', listener: (...args: any[]) => void): this
    public on(eventName: string, listener: (...args: any[]) => void): this {
        super.on(eventName, listener)
        return this
    }

    public once(eventName: 'packet', listener: (pcapPacketInfo: IPcapPacketInfo) => void): this
    public once(eventName: 'done', listener: (...args: any[]) => void): this
    public once(eventName: 'stop', listener: (...args: any[]) => void): this
    public once(eventName: 'close', listener: (...args: any[]) => void): this
    public once(eventName: string, listener: (...args: any[]) => void): this {
        super.once(eventName, listener)
        return this
    }
}
