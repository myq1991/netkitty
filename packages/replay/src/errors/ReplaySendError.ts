import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Emitted as an 'error' event when the native send thread reports a transmit failure. */
export class ReplaySendError extends NetKittyError {
    public errno: number = ErrorCode.E_REPLAY_SEND.errno
    public code: string = ErrorCode.E_REPLAY_SEND.code
}
