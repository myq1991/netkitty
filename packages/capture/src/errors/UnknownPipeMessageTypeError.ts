import {ErrorCode} from './common/ErrorCode'

/** Thrown when a message arrives over the pipe with a type the handler does not recognise. */
export class UnknownPipeMessageTypeError extends Error implements NodeJS.ErrnoException {
    public errno: number = ErrorCode.E_UNKNOWN_PIPE_MESSAGE_TYPE.errno
    public code: string = ErrorCode.E_UNKNOWN_PIPE_MESSAGE_TYPE.code
}
