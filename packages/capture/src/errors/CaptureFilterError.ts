import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when the native addon fails to compile or apply the BPF capture filter. */
export class CaptureFilterError extends NetKittyError {
    public errno: number = ErrorCode.E_CAPTURE_FILTER.errno
    public code: string = ErrorCode.E_CAPTURE_FILTER.code
}
