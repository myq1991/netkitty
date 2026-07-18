import {ErrorCode} from './common/ErrorCode'

export class DeviceNotFoundError extends Error implements NodeJS.ErrnoException {
    public errno: number = ErrorCode.E_DEVICE_NOT_FOUND.errno
    public code: string = ErrorCode.E_DEVICE_NOT_FOUND.code
}
