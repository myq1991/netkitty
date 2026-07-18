/**
 * netkitty/pcap — pcap/pcapng file reading, writing and parsing, plus the browser-safe core
 * (generation helpers and the low-level parser state machine). `@netkitty/pcap` already
 * re-exports the shared core symbols (IPcapPacketInfo, GeneratePCAP*, PcapFileFormat), so only
 * the core-only surface (PcapParserCore and its structural types) is added explicitly here to
 * avoid duplicate-export ambiguity.
 */
export * from '@netkitty/pcap'
export {PcapParserCore} from '@netkitty/pcap-core'
export type {
    PcapParserCoreHandlers,
    PcapGlobalHeader,
    PcapSectionHeader,
    PcapRecordHeader
} from '@netkitty/pcap-core'
