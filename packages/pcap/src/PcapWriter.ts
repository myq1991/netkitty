import EventEmitter from 'events'
import {createWriteStream, existsSync, statSync, WriteStream} from 'node:fs'
import {
    GeneratePCAPData,
    GeneratePCAPHeader,
    GeneratePcapngEnhancedPacket,
    GeneratePcapngInterfaceDescription,
    GeneratePcapngSectionHeader,
    IPcapPacketInfo
} from '@netkitty/pcap-core'

export type PcapWriterFormat = 'pcap' | 'pcapng'

//classic pcap record header is 16 bytes; a pcapng Enhanced Packet Block header (block type..original
//length, before the packet data) is 28 bytes
const PCAP_RECORD_HEADER_LENGTH: number = 16
const PCAPNG_EPB_HEADER_LENGTH: number = 28

export interface IPcapWriterOptions {
    filename: string
    /**
     * Output capture-file format. Default 'pcap' (classic libpcap). 'pcapng' writes a Section Header
     * Block + Interface Description Block up front, then one Enhanced Packet Block per frame.
     */
    format?: PcapWriterFormat
    /**
     * Include the raw packet bytes (base64) in the emitted `packet` event info. Default true. Set false
     * when the consumer only needs metadata — skips the per-packet base64 encoding, and the bytes stay
     * in the file on disk.
     */
    includePacketData?: boolean
}

export class PcapWriter extends EventEmitter {

    public readonly filename: string

    protected readonly writeStream: WriteStream

    protected closed: boolean = false

    protected index: number = 0

    protected offset: number = 0

    protected readonly includePacketData: boolean

    protected readonly format: PcapWriterFormat

    public get wroteCount(): number {
        return this.index
    }

    constructor(options: IPcapWriterOptions) {
        super()
        this.filename = options.filename
        this.format = options.format === 'pcapng' ? 'pcapng' : 'pcap'
        this.includePacketData = options.includePacketData !== false
        if (!existsSync(this.filename)) {
            this.writeStream = createWriteStream(this.filename, {autoClose: false, flags: 'w'})
            //pcapng opens with a Section Header Block + one Interface Description Block; classic pcap with
            //its 24-byte global header
            const header: Buffer = this.format === 'pcapng'
                ? Buffer.concat([GeneratePcapngSectionHeader(), GeneratePcapngInterfaceDescription()])
                : GeneratePCAPHeader()
            this.writeStream.write(header)
            this.offset += header.length
        } else {
            this.writeStream = createWriteStream(this.filename, {autoClose: false, flags: 'a'})
            this.offset += statSync(this.filename).size
        }
    }

    /**
     * Write packet to pcap file
     * @param packet
     * @param seconds
     * @param microseconds
     */
    public write(packet: Buffer, seconds: number, microseconds: number): void {
        if (this.closed) return
        this.index += 1
        const startOffset: number = this.offset
        const packetLength: number = packet.length
        //pcapng puts padding + a trailing length after the packet data, so the data is not at the end of
        //the record; derive packetOffset from the fixed front header length instead of from the tail
        const recordHeaderLength: number = this.format === 'pcapng' ? PCAPNG_EPB_HEADER_LENGTH : PCAP_RECORD_HEADER_LENGTH
        const pcapData: Buffer = this.format === 'pcapng'
            ? GeneratePcapngEnhancedPacket({buffer: packet, microsecond: {seconds: seconds, microseconds: microseconds}})
            : GeneratePCAPData({buffer: packet, timestamp: Date.now(), microsecond: {seconds: seconds, microseconds: microseconds}})
        this.offset += pcapData.length
        const packetOffset: number = startOffset + recordHeaderLength
        const wrotePacketInfo: IPcapPacketInfo = {
            index: this.index,
            offset: startOffset,
            length: pcapData.length,
            recordHeaderOffset: startOffset,
            recordHeaderLength: recordHeaderLength,
            packetOffset: packetOffset,
            packetLength: packetLength,
            seconds: seconds,
            microseconds: microseconds,
            nanoseconds: microseconds * 1000,
            packet: this.includePacketData ? packet.toString('base64') : ''
        }
        this.writeStream.write(pcapData, (): boolean => this.emit('packet', wrotePacketInfo))
    }

    /**
     * Close pcap writer
     */
    public async close(): Promise<void> {
        this.closed = true
        return new Promise((resolve: (value: void | PromiseLike<void>) => void, reject: (reason?: any) => void): void => {
            this.writeStream.close((err: NodeJS.ErrnoException | null | undefined): void => err ? reject(err) : resolve())
        })
    }

    public on(eventName: 'packet', listener: (wrotePacketInfo: IPcapPacketInfo) => void): this
    public on(eventName: string, listener: (...args: any[]) => void): this {
        super.on(eventName, listener)
        return this
    }

    public once(eventName: 'packet', listener: (wrotePacketInfo: IPcapPacketInfo) => void): this
    public once(eventName: string, listener: (...args: any[]) => void): this {
        super.once(eventName, listener)
        return this
    }
}
