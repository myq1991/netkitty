import EventEmitter from 'events'
import {FileHandle, FileReadResult, open} from 'node:fs/promises'
import {ReadStream, WriteStream} from 'node:fs'
import DuplexPair from 'duplexpair'
import {PcapParser} from './PcapParser'
import {IPcapPacketInfo} from './interfaces/IPcapPacketInfo'

export interface IPcapReaderOptions {
    filename: string
    watch?: boolean
    chunkSize?: number
    onPacket?: (capPacketInfo: IPcapPacketInfo) => Promise<void> | void
    onStart?: () => Promise<void> | void
    onStop?: () => Promise<void> | void
    onDone?: () => Promise<void> | void
    onError?: (err: Error) => void
}

export class PcapReader extends EventEmitter {

    protected readonly filename: string

    protected readonly watch: boolean

    protected readonly chunkSize: number = 1518 * 10

    protected duplexPair: DuplexPair

    protected parser: PcapParser

    protected index: number = 0

    protected offset: number = 0

    protected readDone: boolean = false

    protected readBufferFileHandle: FileHandle | null = null

    protected onPacket?: (capPacketInfo: IPcapPacketInfo) => Promise<void> | void

    protected onStart?: () => Promise<void> | void

    protected onStop?: () => Promise<void> | void

    protected onDone?: () => Promise<void> | void

    protected onError?: (err: Error) => void

    protected paused: boolean = false

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
        if (options.onPacket) this.onPacket = options.onPacket
        if (options.onStart) this.onStart = options.onStart
        if (options.onStop) this.onStop = options.onStop
        if (options.onDone) this.onDone = options.onDone
        if (options.onError) this.onError = options.onError
    }

    /**
     * Pause read
     * @protected
     */
    protected pauseRead(): void {
        this.readStream.pause()
        this.paused = true
    }

    /**
     * Resume read
     * @protected
     */
    protected resumeRead(): void {
        this.readStream.resume()
        this.paused = false
    }

    /**
     * Initialize reader
     * @protected
     */
    protected initReader(): void {
        this.duplexPair = new DuplexPair()
        this.parser = PcapParser.parse(this.readStream)
        this.parser
            .on('packet', async (pcapPacketInfo: IPcapPacketInfo): Promise<void> => {
                this.index = pcapPacketInfo.index
                this.emit('packet', pcapPacketInfo)
                if (this.onPacket) {
                    this.pauseRead()
                    await this.onPacket(pcapPacketInfo)
                    this.resumeRead()
                }
            })
            .on('error', (err: Error): void => {
                this.emit('error', err)
                if (this.onError) this.onError(err)
            })
    }

    /**
     * Reset reader
     * @protected
     */
    protected async reset(): Promise<void> {
        await this.stop()
        this.parser?.removeAllListeners()
        this.index = 0
        this.offset = 0
        this.paused = false
        this.initReader()
    }

    /**
     * Initialize read packet file handle
     * @protected
     */
    protected async initReadPacketFileHandle(): Promise<FileHandle> {
        return await open(this.filename, 'r')
    }

    /**
     * Initialize read buffer file handle
     * @protected
     */
    protected async initReadBufferFileHandle(): Promise<FileHandle> {
        if (!this.readBufferFileHandle) this.readBufferFileHandle = await open(this.filename, 'r')
        return this.readBufferFileHandle
    }

    /**
     * Read file buffer
     * @protected
     */
    protected async readBuffer(): Promise<boolean> {
        const readBufferFileHandle: FileHandle = await this.initReadBufferFileHandle()
        try {
            const result: FileReadResult<Buffer> = await readBufferFileHandle.read({
                buffer: Buffer.alloc(this.chunkSize),
                offset: 0,
                length: this.chunkSize,
                position: this.offset
            })
            if (result.bytesRead <= 0) return true
            const data: Buffer = Buffer.alloc(result.bytesRead)
            result.buffer.copy(data, 0, 0, result.bytesRead)
            this.offset += result.bytesRead
            this.writeStream.write(data)
            return false
        } catch (e) {
            return true
        }
    }

    /**
     * Read file continually
     * @protected
     */
    protected continualRead(): void {
        process.nextTick(async (): Promise<void> => {
            let read: boolean = true
            this.once('stop', (): boolean => read = false)
            let isReachEnd: boolean = false
            while (read || !isReachEnd) {
                if (this.paused) {
                    await new Promise(resolve => setTimeout(resolve, 1))
                    continue
                }
                isReachEnd = await this.readBuffer()
                if (isReachEnd) {
                    await new Promise(resolve => setTimeout(resolve, 1))
                }
            }
            await this.readBufferFileHandle?.close()
            this.readBufferFileHandle = null
            this.readDone = true
            this.emit('done')
            if (this.onDone) await this.onDone()
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
                if (this.paused) {
                    await new Promise(resolve => setTimeout(resolve, 1))
                    continue
                }
                isReachEnd = await this.readBuffer()
            }
            this.readDone = true
            if (!stopped) await this.stop()
            await this.readBufferFileHandle?.close()
            this.readBufferFileHandle = null
            this.emit('done')
            if (this.onDone) await this.onDone()
        })
    }

    /**
     * Read packet data by record's offset and record's length
     * @param offset
     * @param length
     */
    public async readPacket(offset: number, length: number): Promise<Buffer> {
        const fileHandle: FileHandle = await this.initReadPacketFileHandle()
        const recordHeaderLength: number = 16
        const packetLength: number = length - recordHeaderLength
        const result: FileReadResult<Buffer> = await fileHandle.read({
            buffer: Buffer.alloc(packetLength),
            offset: 0,
            length: packetLength,
            position: offset + recordHeaderLength
        })
        await fileHandle.close()
        return result.buffer
    }

    /**
     * Start reading pcap
     */
    public async start(): Promise<void> {
        await this.reset()
        this.emit('start')
        if (this.onStart) await this.onStart()
        if (this.watch) {
            this.continualRead()
        } else {
            this.straightRead()
        }
    }

    /**
     * Stop reading pcap
     */
    public async stop(): Promise<void> {
        if (this.parser) {
            this.emit('stop')
            if (!this.readDone) await new Promise(resolve => this.once('done', resolve))
            if (this.onStop) await this.onStop()
        }
        if (this.duplexPair) {
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
        }
    }

    /**
     * Close pcap reader
     */
    public async close(): Promise<void> {
        await this.stop()
        this.emit('close')
        this.removeAllListeners()
    }

    public on(eventName: 'packet', listener: (pcapPacketInfo: IPcapPacketInfo) => void): this
    public on(eventName: 'done', listener: (...args: any[]) => void): this
    public on(eventName: 'start', listener: (...args: any[]) => void): this
    public on(eventName: 'stop', listener: (...args: any[]) => void): this
    public on(eventName: 'close', listener: (...args: any[]) => void): this
    public on(eventName: 'error', listener: (error: Error) => void): this
    public on(eventName: string, listener: (...args: any[]) => void): this {
        super.on(eventName, listener)
        return this
    }

    public once(eventName: 'packet', listener: (pcapPacketInfo: IPcapPacketInfo) => void): this
    public once(eventName: 'done', listener: (...args: any[]) => void): this
    public once(eventName: 'start', listener: (...args: any[]) => void): this
    public once(eventName: 'stop', listener: (...args: any[]) => void): this
    public once(eventName: 'close', listener: (...args: any[]) => void): this
    public once(eventName: 'error', listener: (error: Error) => void): this
    public once(eventName: string, listener: (...args: any[]) => void): this {
        super.once(eventName, listener)
        return this
    }
}
