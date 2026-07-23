import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when a pipe message requests an action name that has no registered handler. */
export class ActionNotFoundError extends NetKittyError {
    public errno: number = ErrorCode.E_ACTION_NOT_FOUND.errno
    public code: string = ErrorCode.E_ACTION_NOT_FOUND.code
}
