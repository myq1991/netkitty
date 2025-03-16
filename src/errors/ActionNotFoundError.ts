import {ErrorCode} from './common/ErrorCode'

export class ActionNotFoundError extends Error implements NodeJS.ErrnoException {
    public errno: number = ErrorCode.E_ACTION_NOT_FOUND.errno
    public code: string = ErrorCode.E_ACTION_NOT_FOUND.code
}
