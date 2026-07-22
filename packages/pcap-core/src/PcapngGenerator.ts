/**
 * Browser-safe, dependency-free generator for pcapng (PCAP Next Generation) capture-file bytes — the
 * write-side counterpart to the parser's pcapng support. It emits a minimal but valid file: one Section
 * Header Block (SHB), one Interface Description Block (IDB), then one Enhanced Packet Block (EPB) per
 * packet. All fields are little-endian (the byte order real tools write); PcapParserCore reads either.
 *
 * Timestamps use microsecond resolution (if_tsresol default, 10^-6 s), matching classic pcap and the
 * PcapWriter API, so the same {seconds, microseconds} / millisecond timestamp inputs as GeneratePCAP work.
 * Timestamps are clamped to safe non-negative integers (a negative would wrap to a huge tick count and a
 * fractional/NaN value would throw), so one odd packet never corrupts or aborts the batch.
 *
 * Per-frame size note: a frame is written verbatim as the block's captured/original length. PcapParserCore
 * enforces a defensive 262144-byte cap (Wireshark's MAX_PACKET_SIZE) on read, so a frame larger than that —
 * which real captures never reach (jumbo ≈ 9 KB, max IPv4 65535) — produces spec-valid bytes that this
 * library's own parser will nonetheless reject rather than silently truncate.
 */
import BigNumber from 'bignumber.js'

export type GeneratePcapngInputPacket = {
    frameBase64Data: string
    timestamp?: number
    microsecond?: {
        seconds: number
        microseconds: number
    }
    interfaceId?: number
}

export type GeneratePcapngPacket = {
    buffer: Buffer
    timestamp?: number
    microsecond?: {
        seconds: number
        microseconds: number
    }
    interfaceId?: number
}

export type GeneratePcapngOptions = {
    //link-layer type of the interface (default 1 = Ethernet); see https://www.tcpdump.org/linktypes.html
    linkLayerType?: number
    //declared snapshot length (default 262144, matching the parser's sane cap)
    snapshotLength?: number
}

const PCAPNG_BLOCK_SECTION_HEADER: number = 0x0a0d0d0a
const PCAPNG_BLOCK_INTERFACE_DESCRIPTION: number = 0x00000001
const PCAPNG_BLOCK_ENHANCED_PACKET: number = 0x00000006
const PCAPNG_BYTE_ORDER_MAGIC: number = 0x1a2b3c4d
const DEFAULT_LINK_LAYER_TYPE: number = 1
const DEFAULT_SNAPSHOT_LENGTH: number = 262144

/**
 * Converts a timestamp in milliseconds to [seconds, microseconds] (same derivation as GeneratePCAP)
 * @param ms
 */
function convertMillisecond2Microsecond(ms: number): [number, number] {
    const [seconds, microseconds] = new BigNumber(ms).dividedBy(1000).toFixed(6).split('.').map((value: string): number => parseInt(value))
    return [seconds, microseconds]
}

/** Pad a buffer's length up to the next 4-byte boundary with zero bytes (pcapng requires 32-bit alignment) */
function padTo4(buffer: Buffer): Buffer {
    const remainder: number = buffer.length % 4
    return remainder === 0 ? buffer : Buffer.concat([buffer, Buffer.alloc(4 - remainder)])
}

/**
 * Generate the Section Header Block that opens a pcapng file
 * @constructor
 */
export function GeneratePcapngSectionHeader(): Buffer {
    const blockTotalLength: number = 28
    const block: Buffer = Buffer.alloc(blockTotalLength)
    block.writeUInt32LE(PCAPNG_BLOCK_SECTION_HEADER, 0)
    block.writeUInt32LE(blockTotalLength, 4)
    block.writeUInt32LE(PCAPNG_BYTE_ORDER_MAGIC, 8)
    block.writeUInt16LE(1, 12) //major version
    block.writeUInt16LE(0, 14) //minor version
    block.fill(0xff, 16, 24) //section length: -1 (unknown)
    block.writeUInt32LE(blockTotalLength, 24) //trailing block total length
    return block
}

/**
 * Generate the Interface Description Block (one interface, microsecond timestamps)
 * @param options
 * @constructor
 */
export function GeneratePcapngInterfaceDescription(options: GeneratePcapngOptions = {}): Buffer {
    const linkLayerType: number = options.linkLayerType ?? DEFAULT_LINK_LAYER_TYPE
    const snapshotLength: number = options.snapshotLength ?? DEFAULT_SNAPSHOT_LENGTH
    const blockTotalLength: number = 20
    const block: Buffer = Buffer.alloc(blockTotalLength)
    block.writeUInt32LE(PCAPNG_BLOCK_INTERFACE_DESCRIPTION, 0)
    block.writeUInt32LE(blockTotalLength, 4)
    block.writeUInt16LE(linkLayerType, 8)
    block.writeUInt16LE(0, 10) //reserved
    block.writeUInt32LE(snapshotLength, 12)
    block.writeUInt32LE(blockTotalLength, 16) //trailing block total length
    return block
}

/**
 * Generate one Enhanced Packet Block for a packet
 * @param packet
 * @constructor
 */
export function GeneratePcapngEnhancedPacket(packet: GeneratePcapngPacket): Buffer {
    let seconds: number
    let microseconds: number
    if (packet.microsecond) {
        seconds = packet.microsecond.seconds
        microseconds = packet.microsecond.microseconds
    } else if (packet.timestamp) {
        [seconds, microseconds] = convertMillisecond2Microsecond(packet.timestamp)
    } else {
        seconds = 0
        microseconds = 0
    }
    //clamp to safe non-negative integers before the BigInt math: a negative wraps to a huge unsigned tick
    //count, and a fractional/NaN value makes BigInt() throw and would abort the whole batch
    seconds = Number.isFinite(seconds) ? Math.max(0, Math.floor(seconds)) : 0
    microseconds = Number.isFinite(microseconds) ? Math.max(0, Math.floor(microseconds)) : 0
    //microsecond-resolution ticks in a 64-bit counter, split into high/low 32-bit words
    const ticks: bigint = BigInt(seconds) * 1000000n + BigInt(microseconds)
    const timestampHigh: number = Number((ticks >> 32n) & 0xffffffffn)
    const timestampLow: number = Number(ticks & 0xffffffffn)

    const paddedData: Buffer = padTo4(packet.buffer)
    const blockTotalLength: number = 28 + paddedData.length + 4
    const header: Buffer = Buffer.alloc(28)
    header.writeUInt32LE(PCAPNG_BLOCK_ENHANCED_PACKET, 0)
    header.writeUInt32LE(blockTotalLength, 4)
    header.writeUInt32LE(packet.interfaceId ?? 0, 8)
    header.writeUInt32LE(timestampHigh, 12)
    header.writeUInt32LE(timestampLow, 16)
    header.writeUInt32LE(packet.buffer.length, 20) //captured length
    header.writeUInt32LE(packet.buffer.length, 24) //original length
    const trailer: Buffer = Buffer.alloc(4)
    trailer.writeUInt32LE(blockTotalLength, 0) //trailing block total length
    return Buffer.concat([header, paddedData, trailer])
}

/**
 * Generate a whole pcapng file: Section Header Block, one Interface Description Block, then one Enhanced
 * Packet Block per packet
 * @param packets
 * @param options
 * @constructor
 */
export function GeneratePcapng(packets: GeneratePcapngInputPacket[] = [], options: GeneratePcapngOptions = {}): Buffer {
    const blocks: Buffer[] = [GeneratePcapngSectionHeader(), GeneratePcapngInterfaceDescription(options)]
    for (const packet of packets) {
        blocks.push(GeneratePcapngEnhancedPacket({
            buffer: Buffer.from(packet.frameBase64Data, 'base64'),
            timestamp: packet.timestamp,
            microsecond: packet.microsecond,
            interfaceId: packet.interfaceId
        }))
    }
    return Buffer.concat(blocks)
}
