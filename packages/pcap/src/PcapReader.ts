import EventEmitter from 'events'
import {gunzipSync} from 'node:zlib'
import {FileHandle, FileReadResult, open, readFile} from 'node:fs/promises'
import {ReadStream, WriteStream, statSync} from 'node:fs'
import DuplexPair from 'duplexpair'
import {PcapParser} from './PcapParser'
import {IPcapPacketInfo, Lz4FrameDecompress, PcapFileFormat} from '@netkitty/pcap-core'

export interface IPcapReaderOptions {
    filename: string
    watch?: boolean
    chunkSize?: number
    onPacket?: (pcapPacketInfo: IPcapPacketInfo) => Promise<void> | void
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

    protected decompressed: Buffer | null = null

    protected decompressError: Error | null = null

    protected onPacket?: (pcapPacketInfo: IPcapPacketInfo) => Promise<void> | void

    protected onStart?: () => Promise<void> | void

    protected onStop?: () => Promise<void> | void

    protected onDone?: () => Promise<void> | void

    protected onError?: (err: Error) => void

    protected paused: boolean = false

    //serialize async onPacket callbacks: a chunk yields many packets synchronously, so their onPacket
    //handlers must run one-at-a-time in packet order (not concurrently, which would reorder the caller's
    //work). pendingOnPacket keeps the read paused until the queued batch drains.
    protected onPacketChain: Promise<void> = Promise.resolve()

    protected pendingOnPacket: number = 0

    //latched on the first onPacket throw: emit 'error' once, then stop invoking the handler (so a later
    //packet can't emit 'error' a second time to a consumed one-shot listener and crash the process)
    protected onPacketErrored: boolean = false

    protected sourceSize: number | null = null

    /**
     * The detected capture-file format ('pcap' | 'pcapng'), or null before the first bytes are parsed
     */
    public get format(): PcapFileFormat | null {
        return this.parser ? this.parser.format : null
    }

    /**
     * Total size of the byte stream the parser walks — the decompressed length for a gzip/LZ4 capture
     * (the parser reports offsets into the decompressed stream), otherwise the on-disk file size. Used to
     * turn a packet's offset into a progress ratio. Returns 0 if the file can't be stat'd.
     */
    public get totalBytes(): number {
        if (this.decompressed) return this.decompressed.length
        if (this.sourceSize === null) {
            try {
                this.sourceSize = statSync(this.filename).size
            } catch {
                this.sourceSize = 0
            }
        }
        return this.sourceSize
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
            .on('packet', (pcapPacketInfo: IPcapPacketInfo): void => {
                this.index = pcapPacketInfo.index
                this.emit('packet', pcapPacketInfo)
                if (this.onPacket) {
                    //append to the serial chain so onPacket runs in packet order, never concurrently
                    this.pendingOnPacket += 1
                    this.pauseRead()
                    this.onPacketChain = this.onPacketChain.then(async (): Promise<void> => {
                        if (!this.onPacketErrored) {
                            try {
                                await this.onPacket!(pcapPacketInfo)
                            } catch (err) {
                                this.onPacketErrored = true
                                this.emit('error', err as Error)
                                if (this.onError) this.onError(err as Error)
                            }
                        }
                        this.pendingOnPacket -= 1
                        if (this.pendingOnPacket === 0) this.resumeRead()
                    })
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
        this.onPacketChain = Promise.resolve()
        this.pendingOnPacket = 0
        this.onPacketErrored = false
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
        if (this.decompressed) {
            if (this.offset >= this.decompressed.length) return true
            const end: number = Math.min(this.offset + this.chunkSize, this.decompressed.length)
            const data: Buffer = Buffer.from(this.decompressed.subarray(this.offset, end))
            this.offset = end
            //an in-memory source has no async I/O to pace it, so honor stream backpressure explicitly —
            //otherwise the whole buffer floods the parser at once and 'done' races ahead of parsing.
            //Resolve on 'close' too, so a concurrent stop()/close() tearing down the stream can't deadlock
            //this wait against stop() awaiting 'done'.
            if (!this.writeStream.write(data)) {
                await new Promise<void>((resolve: () => void): void => {
                    const settle: () => void = (): void => {
                        this.writeStream.off('drain', settle)
                        this.writeStream.off('close', settle)
                        resolve()
                    }
                    this.writeStream.once('drain', settle)
                    this.writeStream.once('close', settle)
                })
            }
            return false
        }
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
                    await new Promise((resolve: (value: unknown) => void): NodeJS.Timeout => setTimeout(resolve, 1))
                    continue
                }
                isReachEnd = await this.readBuffer()
                if (isReachEnd) {
                    await new Promise((resolve: (value: unknown) => void): NodeJS.Timeout => setTimeout(resolve, 1))
                }
            }
            await this.readBufferFileHandle?.close()
            this.readBufferFileHandle = null
            this.readDone = true
            await this.onPacketChain   //let the last queued onPacket batch finish before signalling done
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
                    await new Promise((resolve: (value: unknown) => void): NodeJS.Timeout => setTimeout(resolve, 1))
                    continue
                }
                isReachEnd = await this.readBuffer()
            }
            this.readDone = true
            if (!stopped) await this.stop()
            await this.readBufferFileHandle?.close()
            this.readBufferFileHandle = null
            await this.onPacketChain   //let the last queued onPacket batch finish before signalling done
            this.emit('done')
            if (this.onDone) await this.onDone()
        })
    }

    /**
     * Read packet data by packet info (format-agnostic: works for pcap and pcapng,
     * uses the packetOffset/packetLength the parser reported)
     * @param pcapPacketInfo
     */
    public async readPacketData(pcapPacketInfo: IPcapPacketInfo): Promise<Buffer> {
        if (pcapPacketInfo.packetLength <= 0) return Buffer.from([])
        if (this.decompressed) {
            const start: number = pcapPacketInfo.packetOffset
            return Buffer.from(this.decompressed.subarray(start, start + pcapPacketInfo.packetLength))
        }
        const fileHandle: FileHandle = await this.initReadPacketFileHandle()
        try {
            const result: FileReadResult<Buffer> = await fileHandle.read({
                buffer: Buffer.alloc(pcapPacketInfo.packetLength),
                offset: 0,
                length: pcapPacketInfo.packetLength,
                position: pcapPacketInfo.packetOffset
            })
            return result.buffer.subarray(0, result.bytesRead)
        } finally {
            await fileHandle.close()
        }
    }

    /**
     * Read packet data by record's offset and record's length
     * @deprecated only valid for classic pcap files (assumes a 16-byte record header), use readPacketData instead
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
     * Detect a compressed capture file by its leading magic bytes and, if compressed, decompress the
     * whole file into memory so both the streaming parse and readPacketData() serve the decompressed
     * bytes (the parser reports offsets into the decompressed stream, not the on-disk compressed file).
     * gzip (1f 8b) is handled by node:zlib; LZ4 frame (04 22 4d 18) by the pure-JS Lz4FrameDecompress.
     * Anything else leaves decompressed null and the file is streamed straight from disk as before.
     * @protected
     */
    protected async loadCompressedSource(): Promise<void> {
        this.decompressed = null
        this.decompressError = null
        let magic: Buffer
        try {
            const fileHandle: FileHandle = await open(this.filename, 'r')
            try {
                const result: FileReadResult<Buffer> = await fileHandle.read({
                    buffer: Buffer.alloc(4),
                    offset: 0,
                    length: 4,
                    position: 0
                })
                magic = result.buffer.subarray(0, result.bytesRead)
            } finally {
                await fileHandle.close()
            }
        } catch {
            return //unreadable/missing file — let the normal read path surface it as it did before
        }
        const isGzip: boolean = magic.length >= 2 && magic[0] === 0x1f && magic[1] === 0x8b
        const isLz4: boolean = magic.length >= 4 && magic.readUInt32BE(0) === 0x04224d18
        if (!isGzip && !isLz4) return
        try {
            const fileData: Buffer = await readFile(this.filename)
            this.decompressed = isGzip ? gunzipSync(fileData) : Lz4FrameDecompress(fileData)
        } catch (err) {
            //corrupt/truncated compressed capture — record it so start() can surface a clean 'error'
            //event instead of rejecting, matching how an unknown magic number is handled
            this.decompressed = null
            this.decompressError = err as Error
        }
    }

    /**
     * Start reading pcap
     */
    public async start(): Promise<void> {
        await this.reset()
        await this.loadCompressedSource()
        this.emit('start')
        if (this.onStart) await this.onStart()
        if (this.decompressError) {
            const err: Error = this.decompressError
            this.emit('error', err)
            if (this.onError) this.onError(err)
            this.readDone = true
            this.emit('done')
            if (this.onDone) await this.onDone()
            return
        }
        //a compressed source is a whole-file snapshot decompressed up front, so it can't be tailed —
        //watch mode would idle forever; read it straight through to 'done' instead
        if (this.watch && !this.decompressed) {
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
            if (!this.readDone) await new Promise((resolve: (value: unknown) => void): PcapReader => this.once('done', resolve))
            if (this.onStop) await this.onStop()
        }
        if (this.duplexPair) {
            await new Promise<void>((resolve: (value: void | PromiseLike<void>) => void): void => {
                if (this.writeStream.closed) return resolve()
                this.writeStream.once('close', () => resolve())
                this.writeStream.once('error', (err: Error): boolean => !!err)
                this.writeStream.destroy()
            })
            await new Promise<void>((resolve: (value: void | PromiseLike<void>) => void): void => {
                if (this.readStream.closed) return resolve()
                this.readStream.once('close', () => resolve())
                this.readStream.once('error', (err: Error): boolean => !!err)
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
