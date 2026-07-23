import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when an in-place patch replacement is not the same byte length as the packet it replaces. */
export class PcapPatchLengthError extends NetKittyError {
    public errno: number = ErrorCode.E_PCAP_PATCH_LENGTH.errno
    public code: string = ErrorCode.E_PCAP_PATCH_LENGTH.code
}
