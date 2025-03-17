import EventEmitter from 'events'
import {createWriteStream, WriteStream} from 'node:fs'
import {GeneratePCAPData, GeneratePCAPHeader} from './PCAPGenerator'
import {IPcapPacketInfo} from './interfaces/IPcapPacketInfo'

export interface IPcapWriterOptions {
    filename: string
}

export class PcapWriter extends EventEmitter {

    public readonly filename: string

    protected readonly writeStream: WriteStream

    protected closed: boolean = false

    protected index: number = 0

    protected offset: number = 0

    public get wroteCount(): number {
        return this.index
    }

    constructor(options: IPcapWriterOptions) {
        super()
        this.filename = options.filename
        this.writeStream = createWriteStream(this.filename, {autoClose: false, flags: 'w'})
        const header: Buffer = GeneratePCAPHeader()
        this.writeStream.write(header)
        this.offset += header.length
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
        const pcapData: Buffer = GeneratePCAPData({
            buffer: packet,
            timestamp: Date.now(),
            microsecond: {
                seconds: seconds,
                microseconds: microseconds
            }
        })
        this.offset += pcapData.length
        const packetOffset: number = this.offset - packetLength
        const recordHeaderLength: number = packetOffset - startOffset
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
            packet: packet.toString('base64')
        }
        this.writeStream.write(pcapData, (): boolean => this.emit('packet', wrotePacketInfo))
    }

    /**
     * Close pcap writer
     */
    public async close(): Promise<void> {
        this.closed = true
        return new Promise((resolve, reject): void => {
            this.writeStream.close(err => err ? reject(err) : resolve())
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
