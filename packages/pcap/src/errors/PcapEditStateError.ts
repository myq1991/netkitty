import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when a PcapEdit operation is invalid for the current state (same input/output file, or an in-place patch of a compressed capture). */
export class PcapEditStateError extends NetKittyError {
    public errno: number = ErrorCode.E_PCAP_EDIT_STATE.errno
    public code: string = ErrorCode.E_PCAP_EDIT_STATE.code
}
