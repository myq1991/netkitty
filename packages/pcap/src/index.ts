/**
 * PCAP reader
 */
export {PcapReader, type IPcapReaderOptions} from './PcapReader'
/**
 * PCAP writer
 */
export {PcapWriter, type IPcapWriterOptions} from './PcapWriter'
/**
 * PCAP parser
 */
export {PcapParser, type PcapFileFormat} from './PcapParser'
/**
 * PCAP stream editing (rewrite / patch-in-place + composable transforms)
 */
export {
    PcapEdit,
    type PcapEditPacket,
    type PcapEditAction,
    type PcapEditHandler,
    type PcapEditContext,
    type PcapEditTransform,
    type IPcapRewriteOptions,
    type IPcapRewriteResult,
    type IPcapProgress,
    type IPcapRetimeOptions,
    type RetimeEdit,
    type FrameRange,
    type TimeUnit
} from './PcapEdit'
/**
 * Types and buffer helpers re-exported from the browser-safe core
 */
export {
    type IPcapPacketInfo,
    type GeneratePCAPInputPacket,
    type GeneratePCAPPacket,
    GeneratePCAPHeader,
    GeneratePCAPData,
    GeneratePCAP,
    type GeneratePcapngInputPacket,
    type GeneratePcapngPacket,
    type GeneratePcapngOptions,
    GeneratePcapngSectionHeader,
    GeneratePcapngInterfaceDescription,
    GeneratePcapngEnhancedPacket,
    GeneratePcapng,
    Lz4FrameDecompress
} from '@netkitty/pcap-core'
/**
 * Error classes (all extend NetKittyError)
 */
export * from './errors'
