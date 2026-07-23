import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when the requested capture device is not among the available network interfaces. */
export class DeviceNotFoundError extends NetKittyError {
    public errno: number = ErrorCode.E_DEVICE_NOT_FOUND.errno
    public code: string = ErrorCode.E_DEVICE_NOT_FOUND.code
}
