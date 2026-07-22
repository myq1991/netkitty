/**
 * 由pcap-generator库改写
 * @see:https://github.com/onomondo/pcap-generator/tree/master
 */
import BigNumber from 'bignumber.js'

//classic libpcap magic number for a microsecond-resolution, big-endian file (0xA1B2C3D4)
const PCAP_MAGIC_MICROSECONDS_BE: number = 0xa1b2c3d4

export type GeneratePCAPInputPacket = {
    frameBase64Data: string
    timestamp?: number
    microsecond?: {
        seconds: number
        microseconds: number
    }
}

export type GeneratePCAPPacket = {
    buffer: Buffer,
    timestamp?: number,
    microsecond?: {
        seconds: number
        microseconds: number
    }
}

const headerOptions: {
    majorVersion: number//Major version of pcap. Default: 2
    minorVersion: number//Minor version of pcap. Default: 4
    gmtOffset: number//The GMT offset in pcap. Default: 0
    timestampAccuracy: number//The accuracy of the timestamps. Default: 0
    snapshotLength: number//The snapshot length of the packets. Default: 65535
    linkLayerType: number//The type of packets in the file. E.g. 1 for Ethernet packets, or 101 for raw IP packets. See https://www.tcpdump.org/linktypes.html for more details Default: 1 (Ethernet)
} = {
    majorVersion: 2,
    minorVersion: 4,
    gmtOffset: 0,
    timestampAccuracy: 0,
    snapshotLength: 65535,
    linkLayerType: 1
}

function generate(packets: GeneratePCAPPacket[]): Buffer {
    const globalHeader: Buffer = GeneratePCAPHeader()
    const packetsBuffer: Buffer = Buffer.concat(packets.map((packet: GeneratePCAPPacket): Buffer => GeneratePCAPData(packet)))
    return Buffer.concat([globalHeader, packetsBuffer])
}

/**
 * Converts a timestamp in milliseconds to an integer of the seconds part and an integer of the microseconds part
 *
 * @param ms
 */
function convertMillisecond2Microsecond(ms: number): [number, number] {
    const [seconds, microseconds] = new BigNumber(ms).dividedBy(1000).toFixed(6).split('.').map((value: string): number => parseInt(value))
    return [seconds, microseconds]
}

/**
 * Generate pcap file header's buffer
 * @constructor
 */
export function GeneratePCAPHeader(): Buffer {
    const globalHeader: Buffer = Buffer.alloc(24)
    globalHeader.writeUInt32BE(PCAP_MAGIC_MICROSECONDS_BE, 0) // 4
    globalHeader.writeUInt16BE(headerOptions.majorVersion, 4) // 2
    globalHeader.writeUInt16BE(headerOptions.minorVersion, 6) // 2
    globalHeader.writeInt32BE(headerOptions.gmtOffset, 8) // 4
    globalHeader.writeUInt32BE(headerOptions.timestampAccuracy, 12) // 4
    globalHeader.writeUInt32BE(headerOptions.snapshotLength, 16) // 4
    globalHeader.writeUInt32BE(headerOptions.linkLayerType, 20) // 4
    return globalHeader
}

/**
 * Generate single record data in pcap file
 * @param packet
 * @constructor
 */
export function GeneratePCAPData(packet: GeneratePCAPPacket): Buffer {
    const packetHeader: Buffer = Buffer.alloc(16)
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
    //clamp to safe non-negative integers (a negative/NaN/fractional value would throw or corrupt), then
    //carry any microsecond overflow into seconds so the µs field stays within its valid 0..999999 range —
    //matches the pcapng generator's timestamp handling. Seconds wrap at the 32-bit field width.
    seconds = Number.isFinite(seconds) ? Math.max(0, Math.floor(seconds)) : 0
    microseconds = Number.isFinite(microseconds) ? Math.max(0, Math.floor(microseconds)) : 0
    seconds += Math.floor(microseconds / 1000000)
    microseconds = microseconds % 1000000
    packetHeader.writeUInt32BE(seconds % 0x100000000, 0) // 4 - timestamp seconds
    packetHeader.writeUInt32BE(microseconds, 4) // 4 - timestamp microseconds (0..999999)
    packetHeader.writeUInt32BE(packet.buffer.length, 8) // 4 - captured length
    packetHeader.writeUInt32BE(packet.buffer.length, 12) // 4 - original length

    return Buffer.concat([packetHeader, packet.buffer])
}

/**
 * Generate whole pcap file buffer data
 * @param packets
 * @constructor
 */
export function GeneratePCAP(packets: GeneratePCAPInputPacket[] = []): Buffer {
    return generate(packets.map((packet: GeneratePCAPInputPacket): GeneratePCAPPacket => ({
        timestamp: packet.timestamp,
        microsecond: packet.microsecond,
        buffer: Buffer.from(packet.frameBase64Data, 'base64')
    })))
}
