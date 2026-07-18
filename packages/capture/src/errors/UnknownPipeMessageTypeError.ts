import {ErrorCode} from './common/ErrorCode'

export class UnknownPipeMessageTypeError extends Error implements NodeJS.ErrnoException {
    public errno: number = ErrorCode.E_UNKNOWN_PIPE_MESSAGE_TYPE.errno
    public code: string = ErrorCode.E_UNKNOWN_PIPE_MESSAGE_TYPE.code
}
