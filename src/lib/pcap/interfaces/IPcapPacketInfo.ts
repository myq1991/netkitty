export interface IPcapPacketInfo {
    index: number
    offset: number
    length: number
    recordHeaderOffset:number
    recordHeaderLength:number
    packetOffset: number
    packetLength: number
    seconds: number
    microseconds: number
    packet: string
}
