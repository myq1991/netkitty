import EventEmitter from 'events'
import {createReadStream, ReadStream} from 'node:fs'
import {format} from 'node:util'
import {IPcapPacketInfo} from '../interfaces/IPcapPacketInfo'

const GLOBAL_HEADER_LENGTH = 24 //bytes
const PACKET_HEADER_LENGTH = 16 //bytes

export class PcapParser extends EventEmitter {

    protected stream: ReadStream

    protected buffer: Buffer | null

    protected errored: boolean = false

    protected endianness: 'BE' | 'LE' | null

    protected index: number = 0

    protected state: () => boolean

    protected offset: number = 0

    protected currentPacketHeader: {
        timestampSeconds: number
        timestampMicroseconds: number
        capturedLength: number
        originalLength: number
    }

    public static parse(input: string | ReadStream): PcapParser {
        return new PcapParser(input)
    }

    constructor(input: string | ReadStream) {
        super()
        this.stream = (typeof input === 'string') ? createReadStream(input) : input
        this.stream.pause()
        this.stream.on('data', (data: string | Buffer): void => this.onData(data as Buffer))
        this.stream.on('error', (err: Error): void => this.onError(err))
        this.stream.on('end', (): void => this.onEnd())
        this.buffer = null
        this.state = () => this.parseGlobalHeader()
        this.endianness = null
        process.nextTick(this.stream.resume.bind(this.stream))
    }

    protected updateBuffer(data: Buffer): void {
        if (data === null || data === undefined) return
        if (this.buffer === null) {
            this.buffer = data
        } else {
            let extendedBuffer: Buffer = Buffer.alloc(this.buffer.length + data.length)
            this.buffer.copy(extendedBuffer)
            data.copy(extendedBuffer, this.buffer.length)
            this.buffer = extendedBuffer
        }
    }

    protected parseGlobalHeader(): boolean {
        const buffer: Buffer = this.buffer!
        if (buffer.length >= GLOBAL_HEADER_LENGTH) {
            let msg: string
            const magicNumber: string = buffer.toString('hex', 0, 4)
            // determine pcap endianness
            if (magicNumber == 'a1b2c3d4') {
                this.endianness = 'BE'
            } else if (magicNumber == 'd4c3b2a1') {
                this.endianness = 'LE'
            } else {
                this.errored = true
                this.stream.pause()
                msg = format('unknown magic number: %s', magicNumber)
                this.emit('error', new Error(msg))
                this.onEnd()
                return false
            }

            const header = {
                magicNumber: buffer['readUInt32' + this.endianness](0, true),
                majorVersion: buffer['readUInt16' + this.endianness](4, true),
                minorVersion: buffer['readUInt16' + this.endianness](6, true),
                gmtOffset: buffer['readInt32' + this.endianness](8, true),
                timestampAccuracy: buffer['readUInt32' + this.endianness](12, true),
                snapshotLength: buffer['readUInt32' + this.endianness](16, true),
                linkLayerType: buffer['readUInt32' + this.endianness](20, true)
            }

            if (header.majorVersion != 2 && header.minorVersion != 4) {
                this.errored = true
                this.stream.pause()
                msg = format('unsupported version %d.%d. pcap-parser only parses libpcap file format 2.4', header.majorVersion, header.minorVersion)
                this.emit('error', new Error(msg))
                this.onEnd()
            } else {
                this.emit('globalHeader', header)
                this.buffer = buffer.subarray(GLOBAL_HEADER_LENGTH)
                this.state = (): boolean => this.parsePacketHeader()
                this.offset = GLOBAL_HEADER_LENGTH
                return true
            }
        }

        return false
    }

    protected parsePacketHeader(): boolean {
        const buffer: Buffer = this.buffer!
        if (buffer.length >= PACKET_HEADER_LENGTH) {
            const header = {
                timestampSeconds: buffer['readUInt32' + this.endianness](0, true),
                timestampMicroseconds: buffer['readUInt32' + this.endianness](4, true),
                capturedLength: buffer['readUInt32' + this.endianness](8, true),
                originalLength: buffer['readUInt32' + this.endianness](12, true)
            }
            this.currentPacketHeader = header
            this.emit('packetHeader', header)
            this.buffer = buffer.subarray(PACKET_HEADER_LENGTH)
            this.state = (): boolean => this.parsePacketBody()
            this.index += 1
            return true
        }
        return false
    }

    protected parsePacketBody(): boolean {
        const buffer: Buffer = this.buffer!

        if (buffer.length >= this.currentPacketHeader.capturedLength) {
            const data: Buffer = buffer.subarray(0, this.currentPacketHeader!.capturedLength)
            const packetLength: number = data.length
            const pcapPacketInfo: IPcapPacketInfo = {
                index: this.index,
                offset: this.offset,
                timestampOffset: this.offset,
                timestampLength: 16,
                packetOffset: this.offset + PACKET_HEADER_LENGTH,
                packetLength: data.length,
                seconds: this.currentPacketHeader.timestampSeconds,
                microseconds: this.currentPacketHeader.timestampMicroseconds,
                packet: data.toString('base64')
            }
            this.emit('packetData', data)
            this.emit('packet', pcapPacketInfo)
            this.buffer = buffer.subarray(this.currentPacketHeader.capturedLength)
            this.state = (): boolean => this.parsePacketHeader()
            this.offset += (PACKET_HEADER_LENGTH + packetLength)
            return true
        }
        return false
    }

    protected onData(data: Buffer): void {
        if (this.errored) return
        this.updateBuffer(data)
        while (this.state()) {
        }
    }

    protected onError(err: Error): void {
        this.emit('error', err)
    }

    protected onEnd(): void {
        this.emit('end')
    }
}
