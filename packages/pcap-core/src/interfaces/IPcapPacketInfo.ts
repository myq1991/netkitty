/** Metadata for one parsed packet: its index, byte offsets/lengths within the file, capture timestamp, and (optionally) the base64 frame bytes. */
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
