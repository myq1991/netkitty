import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when a pipe operation is attempted but the underlying socket is closed or unavailable. */
export class CaptureSocketDownError extends NetKittyError {
    public errno: number = ErrorCode.E_SOCKET_DOWN.errno
    public code: string = ErrorCode.E_SOCKET_DOWN.code
}
