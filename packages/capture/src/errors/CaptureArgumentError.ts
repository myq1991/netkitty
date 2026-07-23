import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when the native capture addon rejects its arguments (wrong count or type). */
export class CaptureArgumentError extends NetKittyError {
    public errno: number = ErrorCode.E_CAPTURE_ARGUMENT.errno
    public code: string = ErrorCode.E_CAPTURE_ARGUMENT.code
}
