import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when a MAC address argument is not six hex octets like 00:11:22:33:44:55. */
export class PcapInvalidMacError extends NetKittyError {
    public errno: number = ErrorCode.E_PCAP_INVALID_MAC.errno
    public code: string = ErrorCode.E_PCAP_INVALID_MAC.code
}
