/**
 * 由pcap-generator库改写
 * @see:https://github.com/onomondo/pcap-generator/tree/master
 */
import BigNumber from 'bignumber.js'

export type GeneratePCAPInputPacket = {
    timestamp: number
    frameBase64Data: string
    microsecond?: {
        seconds: number
        microseconds: number
    }
}

export type GeneratePCAPPacket = {
    buffer: Buffer,
    timestamp: number,
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
    linkLayerType: number//The type of packets in the file. E.g. 101 for raw IP packets, or 1 for Ethernet packets. See https://www.tcpdump.org/linktypes.html for more details Default: 101 (Raw IP packets)
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
    const [seconds, microseconds] = new BigNumber(ms).dividedBy(1000).toFixed(6).split('.').map(value => parseInt(value))
    return [seconds, microseconds]
}

function makeLessThanAMillion(i: number): number {
    while (i > 1000000) {
        i = Math.floor(i / 10)
    }
    return i
}

/**
 * Generate pcap file header's buffer
 * @constructor
 */
export function GeneratePCAPHeader(): Buffer {
    const globalHeader: Buffer = Buffer.alloc(24)
    globalHeader.writeUInt32BE(2712847316, 0) // 4
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
    } else {
        [seconds, microseconds] = convertMillisecond2Microsecond(packet.timestamp)
    }
    packetHeader.writeUInt32BE(seconds, 0) // 4
    if (packet.microsecond) {
        packetHeader.writeUInt32BE(microseconds, 4) // 4 - if in microsecond precision then remove excess of 1,000,000 (see documentation)
    } else {
        packetHeader.writeUInt32BE(makeLessThanAMillion(microseconds), 4) // 4 - if in microsecond precision then remove excess of 1,000,000 (see documentation)
    }
    packetHeader.writeUInt32BE(packet.buffer.length, 8) // 4
    packetHeader.writeUInt32BE(packet.buffer.length, 12) // 4

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
