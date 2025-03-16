export interface IPcapPacketInfo {
    index: number
    offset: number
    length: number
    timestampOffset: number
    timestampLength: number
    packetOffset: number
    packetLength: number
    seconds: number
    microseconds: number
    packet: string
}
