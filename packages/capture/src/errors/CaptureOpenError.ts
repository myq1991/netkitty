import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when the native addon fails to open the capture device (pcap_open_live returned an error). */
export class CaptureOpenError extends NetKittyError {
    public errno: number = ErrorCode.E_CAPTURE_OPEN.errno
    public code: string = ErrorCode.E_CAPTURE_OPEN.code
}
