import EventEmitter from 'events'
import {createReadStream, ReadStream} from 'node:fs'
import {
    IPcapPacketInfo,
    PcapFileFormat,
    PcapGlobalHeader,
    PcapParserCore,
    PcapRecordHeader,
    PcapSectionHeader
} from '@netkitty/pcap-core'

export type {PcapFileFormat} from '@netkitty/pcap-core'

/**
 * Streaming pcap/pcapng parser: a thin EventEmitter shell around PcapParserCore.
 * The node:fs read stream feeds bytes into the pure core, whose result callbacks
 * are re-emitted as the original events (globalHeader/sectionHeader/packetHeader/
 * packetData/packet/end/error).
 */
export class PcapParser extends EventEmitter {

    protected stream: ReadStream

    protected core: PcapParserCore

    public get format(): PcapFileFormat | null {
        return this.core.format
    }

    public static parse(input: string | ReadStream): PcapParser {
        return new PcapParser(input)
    }

    constructor(input: string | ReadStream) {
        super()
        this.core = new PcapParserCore({
            onGlobalHeader: (header: PcapGlobalHeader): boolean => this.emit('globalHeader', header),
            onSectionHeader: (header: PcapSectionHeader): boolean => this.emit('sectionHeader', header),
            onPacketHeader: (header: PcapRecordHeader): boolean => this.emit('packetHeader', header),
            onPacketData: (data: Buffer): boolean => this.emit('packetData', data),
            onPacket: (pcapPacketInfo: IPcapPacketInfo): boolean => this.emit('packet', pcapPacketInfo),
            onEnd: (): boolean => this.emit('end'),
            onError: (err: Error): void => this.onError(err)
        })
        this.stream = (typeof input === 'string') ? createReadStream(input) : input
        this.stream.pause()
        this.stream.on('data', (data: string | Buffer): void => this.core.write(data as Buffer))
        this.stream.on('error', (err: Error): void => this.onError(err))
        this.stream.on('end', (): void => this.core.end())
        process.nextTick(this.stream.resume.bind(this.stream))
    }

    protected onError(err: Error): void {
        this.stream.pause()
        this.emit('error', err)
    }
}
