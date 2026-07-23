import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when a PcapEdit call receives an invalid argument (bad range, scale factor, or time unit). */
export class PcapEditArgumentError extends NetKittyError {
    public errno: number = ErrorCode.E_PCAP_EDIT_ARGUMENT.errno
    public code: string = ErrorCode.E_PCAP_EDIT_ARGUMENT.code
}
