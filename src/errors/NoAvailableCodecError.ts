import {ErrorCode} from './common/ErrorCode'

export class NoAvailableCodecError extends Error implements NodeJS.ErrnoException {
    public errno: number = ErrorCode.E_NO_AVAILABLE_CODEC.errno
    public code: string = ErrorCode.E_NO_AVAILABLE_CODEC.code
}
