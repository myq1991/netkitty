import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when a buffer is not a structurally valid LZ4 frame (bad magic, too short, or an unsupported version). */
export class PcapLz4FrameError extends NetKittyError {
    public errno: number = ErrorCode.E_PCAP_LZ4_FRAME.errno
    public code: string = ErrorCode.E_PCAP_LZ4_FRAME.code
}
