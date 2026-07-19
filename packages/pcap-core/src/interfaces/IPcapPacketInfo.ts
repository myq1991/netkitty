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
    //sub-second fraction in nanoseconds (0..999_999_999); full ns precision for ns pcap / pcapng if_tsresol
    nanoseconds: number
    packet: string
}
