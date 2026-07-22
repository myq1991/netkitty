import {ErrorCode} from './common/ErrorCode'

/** Thrown when the requested capture device is not among the available network interfaces. */
export class DeviceNotFoundError extends Error implements NodeJS.ErrnoException {
    public errno: number = ErrorCode.E_DEVICE_NOT_FOUND.errno
    public code: string = ErrorCode.E_DEVICE_NOT_FOUND.code
}
