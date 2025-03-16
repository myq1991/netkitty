import {ErrorCode} from './common/ErrorCode'

export class SocketDownError extends Error implements NodeJS.ErrnoException {
    public errno: number = ErrorCode.E_SOCKET_DOWN.errno
    public code: string = ErrorCode.E_SOCKET_DOWN.code
}
