import {ErrorCode} from './common/ErrorCode'

/** Thrown when a pipe operation is attempted but the underlying socket is closed or unavailable. */
export class SocketDownError extends Error implements NodeJS.ErrnoException {
    public errno: number = ErrorCode.E_SOCKET_DOWN.errno
    public code: string = ErrorCode.E_SOCKET_DOWN.code
}
