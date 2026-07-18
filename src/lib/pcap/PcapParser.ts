import EventEmitter from 'events'
import {createReadStream, ReadStream} from 'node:fs'
import {format} from 'node:util'
import {IPcapPacketInfo} from './interfaces/IPcapPacketInfo'

const PCAP_GLOBAL_HEADER_LENGTH: number = 24 //bytes
const PCAP_PACKET_HEADER_LENGTH: number = 16 //bytes
const PCAPNG_EPB_HEADER_LENGTH: number = 28 //bytes (block type..original length, before packet data)
const PCAPNG_SPB_HEADER_LENGTH: number = 12 //bytes
//Sane upper bound for a single captured packet (matches Wireshark's MAX_PACKET_SIZE)
const MAX_CAPTURED_LENGTH: number = 262144
//Sane upper bound for a single pcapng block (packet block header + max packet + options headroom)
const MAX_BLOCK_LENGTH: number = MAX_CAPTURED_LENGTH + 4096

//pcapng block types
const PCAPNG_BLOCK_SECTION_HEADER: number = 0x0a0d0d0a
const PCAPNG_BLOCK_INTERFACE_DESCRIPTION: number = 0x00000001
const PCAPNG_BLOCK_OBSOLETE_PACKET: number = 0x00000002
const PCAPNG_BLOCK_SIMPLE_PACKET: number = 0x00000003
const PCAPNG_BLOCK_ENHANCED_PACKET: number = 0x00000006

type PcapNgInterface = {
    linkLayerType: number
    snapshotLength: number
    //if_tsresol: timestamp tick is base^-exponent seconds (default 10^-6, microseconds)
    timestampBase: 10 | 2
    timestampExponent: number
}

export type PcapFileFormat = 'pcap' | 'pcapng'

export class PcapParser extends EventEmitter {

    protected stream: ReadStream

    protected buffer: Buffer | null

    protected errored: boolean = false

    protected endianness: 'BE' | 'LE' | null

    protected index: number = 0

    protected state: () => boolean

    protected offset: number = 0

    protected fileFormat: PcapFileFormat | null = null

    //classic pcap: second timestamp field holds nanoseconds instead of microseconds
    protected timestampNanosecond: boolean = false

    protected ngInterfaces: PcapNgInterface[] = []

    protected currentPacketHeader: {
        timestampSeconds: number
        timestampMicroseconds: number
        capturedLength: number
        originalLength: number
    }

    public get format(): PcapFileFormat | null {
        return this.fileFormat
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
        this.state = (): boolean => this.detectFormat()
        this.endianness = null
        process.nextTick(this.stream.resume.bind(this.stream))
    }

    protected updateBuffer(data: Buffer): void {
        if (data === null || data === undefined) return
        if (this.buffer === null) {
            this.buffer = data
        } else {
            const extendedBuffer: Buffer = Buffer.alloc(this.buffer.length + data.length)
            this.buffer.copy(extendedBuffer)
            data.copy(extendedBuffer, this.buffer.length)
            this.buffer = extendedBuffer
        }
    }

    protected readUInt32(buffer: Buffer, offset: number): number {
        return this.endianness === 'BE' ? buffer.readUInt32BE(offset) : buffer.readUInt32LE(offset)
    }

    protected readUInt16(buffer: Buffer, offset: number): number {
        return this.endianness === 'BE' ? buffer.readUInt16BE(offset) : buffer.readUInt16LE(offset)
    }

    protected readInt32(buffer: Buffer, offset: number): number {
        return this.endianness === 'BE' ? buffer.readInt32BE(offset) : buffer.readInt32LE(offset)
    }

    /**
     * Enter error state and stop parsing
     * @param message
     * @protected
     */
    protected fail(message: string): false {
        this.errored = true
        this.stream.pause()
        this.emit('error', new Error(message))
        this.onEnd()
        return false
    }

    /**
     * Detect capture file format by magic number.
     * Classic libpcap (.pcap/.cap/tcpdump output): 4 magic variants (endianness × µs/ns).
     * pcapng: section header block type 0x0A0D0D0A.
     * @protected
     */
    protected detectFormat(): boolean {
        const buffer: Buffer = this.buffer!
        if (buffer === null || buffer.length < 4) return false
        const magicNumber: string = buffer.toString('hex', 0, 4)
        switch (magicNumber) {
            case 'a1b2c3d4':
                this.fileFormat = 'pcap'
                this.endianness = 'BE'
                this.timestampNanosecond = false
                break
            case 'd4c3b2a1':
                this.fileFormat = 'pcap'
                this.endianness = 'LE'
                this.timestampNanosecond = false
                break
            case 'a1b23c4d':
                this.fileFormat = 'pcap'
                this.endianness = 'BE'
                this.timestampNanosecond = true
                break
            case '4d3cb2a1':
                this.fileFormat = 'pcap'
                this.endianness = 'LE'
                this.timestampNanosecond = true
                break
            case '0a0d0d0a':
                this.fileFormat = 'pcapng'
                this.state = (): boolean => this.parseNgBlock()
                return true
            default:
                return this.fail(format('unknown magic number: %s', magicNumber))
        }
        this.state = (): boolean => this.parseGlobalHeader()
        return true
    }

    /**
     * Classic pcap: global header
     * @protected
     */
    protected parseGlobalHeader(): boolean {
        const buffer: Buffer = this.buffer!
        if (buffer.length >= PCAP_GLOBAL_HEADER_LENGTH) {
            const header = {
                magicNumber: this.readUInt32(buffer, 0),
                majorVersion: this.readUInt16(buffer, 4),
                minorVersion: this.readUInt16(buffer, 6),
                gmtOffset: this.readInt32(buffer, 8),
                timestampAccuracy: this.readUInt32(buffer, 12),
                snapshotLength: this.readUInt32(buffer, 16),
                linkLayerType: this.readUInt32(buffer, 20)
            }
            if (header.majorVersion !== 2) {
                return this.fail(format('unsupported version %d.%d, only libpcap file format 2.x is supported', header.majorVersion, header.minorVersion))
            }
            this.emit('globalHeader', header)
            this.buffer = buffer.subarray(PCAP_GLOBAL_HEADER_LENGTH)
            this.state = (): boolean => this.parsePacketHeader()
            this.offset = PCAP_GLOBAL_HEADER_LENGTH
            return true
        }
        return false
    }

    /**
     * Classic pcap: per-packet record header
     * @protected
     */
    protected parsePacketHeader(): boolean {
        const buffer: Buffer = this.buffer!
        if (buffer.length >= PCAP_PACKET_HEADER_LENGTH) {
            const timestampFraction: number = this.readUInt32(buffer, 4)
            const header = {
                timestampSeconds: this.readUInt32(buffer, 0),
                timestampMicroseconds: this.timestampNanosecond ? Math.floor(timestampFraction / 1000) : timestampFraction,
                capturedLength: this.readUInt32(buffer, 8),
                originalLength: this.readUInt32(buffer, 12)
            }
            if (header.capturedLength > MAX_CAPTURED_LENGTH) {
                return this.fail(format('corrupt capture file: captured length %d exceeds sane limit %d', header.capturedLength, MAX_CAPTURED_LENGTH))
            }
            this.currentPacketHeader = header
            this.emit('packetHeader', header)
            this.buffer = buffer.subarray(PCAP_PACKET_HEADER_LENGTH)
            this.state = (): boolean => this.parsePacketBody()
            this.index += 1
            return true
        }
        return false
    }

    /**
     * Classic pcap: packet data
     * @protected
     */
    protected parsePacketBody(): boolean {
        const buffer: Buffer = this.buffer!

        if (buffer.length >= this.currentPacketHeader.capturedLength) {
            const data: Buffer = buffer.subarray(0, this.currentPacketHeader!.capturedLength)
            const packetLength: number = data.length
            const recordLength: number = PCAP_PACKET_HEADER_LENGTH + packetLength
            const pcapPacketInfo: IPcapPacketInfo = {
                index: this.index,
                offset: this.offset,
                length: recordLength,
                recordHeaderOffset: this.offset,
                recordHeaderLength: PCAP_PACKET_HEADER_LENGTH,
                packetOffset: this.offset + PCAP_PACKET_HEADER_LENGTH,
                packetLength: data.length,
                seconds: this.currentPacketHeader.timestampSeconds,
                microseconds: this.currentPacketHeader.timestampMicroseconds,
                packet: data.toString('base64')
            }
            this.emit('packetData', data)
            this.emit('packet', pcapPacketInfo)
            this.buffer = buffer.subarray(this.currentPacketHeader.capturedLength)
            this.state = (): boolean => this.parsePacketHeader()
            this.offset += recordLength
            return true
        }
        return false
    }

    /**
     * pcapng: timestamp ticks (64bit, split high/low) → seconds + microseconds
     * @param ngInterface
     * @param timestampHigh
     * @param timestampLow
     * @protected
     */
    protected ngTimestamp(ngInterface: PcapNgInterface, timestampHigh: number, timestampLow: number): { seconds: number, microseconds: number } {
        const ticks: bigint = (BigInt(timestampHigh) << 32n) | BigInt(timestampLow)
        const divisor: bigint = ngInterface.timestampBase === 2
            ? 2n ** BigInt(ngInterface.timestampExponent)
            : 10n ** BigInt(ngInterface.timestampExponent)
        return {
            seconds: Number(ticks / divisor),
            microseconds: Number(((ticks % divisor) * 1000000n) / divisor)
        }
    }

    /**
     * pcapng: interface of a packet block (default: µs resolution, 262144 snaplen)
     * @param interfaceId
     * @protected
     */
    protected ngInterface(interfaceId: number): PcapNgInterface {
        const found: PcapNgInterface | undefined = this.ngInterfaces[interfaceId]
        return found ? found : {
            linkLayerType: 1,
            snapshotLength: MAX_CAPTURED_LENGTH,
            timestampBase: 10,
            timestampExponent: 6
        }
    }

    /**
     * pcapng: parse the options area of an interface description block for if_tsresol
     * @param buffer whole block buffer
     * @param optionsStart
     * @param optionsEnd
     * @param ngInterface
     * @protected
     */
    protected ngParseInterfaceOptions(buffer: Buffer, optionsStart: number, optionsEnd: number, ngInterface: PcapNgInterface): void {
        let position: number = optionsStart
        while (position + 4 <= optionsEnd) {
            const optionCode: number = this.readUInt16(buffer, position)
            const optionLength: number = this.readUInt16(buffer, position + 2)
            if (optionCode === 0) return
            //if_tsresol
            if (optionCode === 9 && optionLength >= 1 && position + 4 < optionsEnd) {
                const rawResolution: number = buffer.readUInt8(position + 4)
                if (rawResolution & 0x80) {
                    ngInterface.timestampBase = 2
                    ngInterface.timestampExponent = rawResolution & 0x7f
                } else {
                    ngInterface.timestampBase = 10
                    ngInterface.timestampExponent = rawResolution
                }
            }
            position += 4 + (Math.ceil(optionLength / 4) * 4)
        }
    }

    /**
     * pcapng: emit one packet block as IPcapPacketInfo
     * @protected
     */
    protected ngEmitPacket(blockOffset: number, blockTotalLength: number, recordHeaderLength: number, data: Buffer, seconds: number, microseconds: number, originalLength: number): void {
        this.index += 1
        const header = {
            timestampSeconds: seconds,
            timestampMicroseconds: microseconds,
            capturedLength: data.length,
            originalLength: originalLength
        }
        this.currentPacketHeader = header
        this.emit('packetHeader', header)
        const pcapPacketInfo: IPcapPacketInfo = {
            index: this.index,
            offset: blockOffset,
            length: blockTotalLength,
            recordHeaderOffset: blockOffset,
            recordHeaderLength: recordHeaderLength,
            packetOffset: blockOffset + recordHeaderLength,
            packetLength: data.length,
            seconds: seconds,
            microseconds: microseconds,
            packet: data.toString('base64')
        }
        this.emit('packetData', data)
        this.emit('packet', pcapPacketInfo)
    }

    /**
     * pcapng: parse one block (section header, interface description, packet blocks; others skipped)
     * @protected
     */
    protected parseNgBlock(): boolean {
        const buffer: Buffer = this.buffer!
        if (buffer === null || buffer.length < 12) return false

        //Section header block type is a palindrome, readable before endianness is known
        const isSectionHeader: boolean = buffer.toString('hex', 0, 4) === '0a0d0d0a'
        if (isSectionHeader) {
            const byteOrderMagic: string = buffer.toString('hex', 8, 12)
            if (byteOrderMagic === '1a2b3c4d') {
                this.endianness = 'BE'
            } else if (byteOrderMagic === '4d3c2b1a') {
                this.endianness = 'LE'
            } else {
                return this.fail(format('corrupt pcapng: unknown byte-order magic %s', byteOrderMagic))
            }
        }
        if (!this.endianness) return this.fail('corrupt pcapng: block appears before section header')

        const blockTotalLength: number = this.readUInt32(buffer, 4)
        if (blockTotalLength < 12 || blockTotalLength % 4 !== 0) {
            return this.fail(format('corrupt pcapng: invalid block total length %d', blockTotalLength))
        }
        if (blockTotalLength > MAX_BLOCK_LENGTH) {
            return this.fail(format('corrupt pcapng: block length %d exceeds sane limit %d', blockTotalLength, MAX_BLOCK_LENGTH))
        }
        if (buffer.length < blockTotalLength) return false

        const blockType: number = this.readUInt32(buffer, 0)
        const blockOffset: number = this.offset
        switch (blockType) {
            case PCAPNG_BLOCK_SECTION_HEADER: {
                //New section: interfaces reset (endianness already handled above)
                this.ngInterfaces = []
                this.emit('sectionHeader', {
                    majorVersion: this.readUInt16(buffer, 12),
                    minorVersion: this.readUInt16(buffer, 14)
                })
                break
            }
            case PCAPNG_BLOCK_INTERFACE_DESCRIPTION: {
                const ngInterface: PcapNgInterface = {
                    linkLayerType: this.readUInt16(buffer, 8),
                    snapshotLength: this.readUInt32(buffer, 12),
                    timestampBase: 10,
                    timestampExponent: 6
                }
                this.ngParseInterfaceOptions(buffer, 16, blockTotalLength - 4, ngInterface)
                this.ngInterfaces.push(ngInterface)
                break
            }
            case PCAPNG_BLOCK_ENHANCED_PACKET:
            case PCAPNG_BLOCK_OBSOLETE_PACKET: {
                const interfaceId: number = blockType === PCAPNG_BLOCK_ENHANCED_PACKET ? this.readUInt32(buffer, 8) : this.readUInt16(buffer, 8)
                const timestampHigh: number = this.readUInt32(buffer, 12)
                const timestampLow: number = this.readUInt32(buffer, 16)
                const capturedLength: number = this.readUInt32(buffer, 20)
                const originalLength: number = this.readUInt32(buffer, 24)
                if (capturedLength > MAX_CAPTURED_LENGTH || PCAPNG_EPB_HEADER_LENGTH + capturedLength > blockTotalLength - 4) {
                    return this.fail(format('corrupt pcapng: captured length %d does not fit its block (%d)', capturedLength, blockTotalLength))
                }
                const data: Buffer = buffer.subarray(PCAPNG_EPB_HEADER_LENGTH, PCAPNG_EPB_HEADER_LENGTH + capturedLength)
                const timestamp: { seconds: number, microseconds: number } = this.ngTimestamp(this.ngInterface(interfaceId), timestampHigh, timestampLow)
                this.ngEmitPacket(blockOffset, blockTotalLength, PCAPNG_EPB_HEADER_LENGTH, data, timestamp.seconds, timestamp.microseconds, originalLength)
                break
            }
            case PCAPNG_BLOCK_SIMPLE_PACKET: {
                const originalLength: number = this.readUInt32(buffer, 8)
                const dataAreaLength: number = blockTotalLength - PCAPNG_SPB_HEADER_LENGTH - 4
                const snapshotLength: number = this.ngInterface(0).snapshotLength
                const capturedLength: number = Math.min(originalLength, dataAreaLength, snapshotLength > 0 ? snapshotLength : MAX_CAPTURED_LENGTH)
                if (capturedLength < 0 || capturedLength > MAX_CAPTURED_LENGTH) {
                    return this.fail(format('corrupt pcapng: simple packet length %d is invalid', capturedLength))
                }
                const data: Buffer = buffer.subarray(PCAPNG_SPB_HEADER_LENGTH, PCAPNG_SPB_HEADER_LENGTH + capturedLength)
                this.ngEmitPacket(blockOffset, blockTotalLength, PCAPNG_SPB_HEADER_LENGTH, data, 0, 0, originalLength)
                break
            }
            default:
                //Name resolution, interface statistics, custom/unknown blocks: skip
                break
        }
        this.buffer = buffer.subarray(blockTotalLength)
        this.offset += blockTotalLength
        return true
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
