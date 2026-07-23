import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when the requested replay device is not among the available network interfaces. */
export class ReplayDeviceNotFoundError extends NetKittyError {
    public errno: number = ErrorCode.E_REPLAY_DEVICE_NOT_FOUND.errno
    public code: string = ErrorCode.E_REPLAY_DEVICE_NOT_FOUND.code
}
