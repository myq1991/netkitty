import {ErrorCode, NetKittyError} from '@netkitty/errors'
import {CaptureDeviceNotFoundError} from './CaptureDeviceNotFoundError'
import {CaptureNpcapLoadError} from './CaptureNpcapLoadError'
import {CaptureSocketDownError} from './CaptureSocketDownError'
import {CaptureUnknownPipeMessageTypeError} from './CaptureUnknownPipeMessageTypeError'
import {CaptureActionNotFoundError} from './CaptureActionNotFoundError'
import {CaptureArgumentError} from './CaptureArgumentError'
import {CaptureOpenError} from './CaptureOpenError'
import {CaptureFilterError} from './CaptureFilterError'

const CAPTURE_ERROR_BY_CODE: Record<string, new (message?: string) => NetKittyError> = {
    [ErrorCode.E_DEVICE_NOT_FOUND.code]: CaptureDeviceNotFoundError,
    [ErrorCode.E_NPCAP_LOAD.code]: CaptureNpcapLoadError,
    [ErrorCode.E_SOCKET_DOWN.code]: CaptureSocketDownError,
    [ErrorCode.E_UNKNOWN_PIPE_MESSAGE_TYPE.code]: CaptureUnknownPipeMessageTypeError,
    [ErrorCode.E_ACTION_NOT_FOUND.code]: CaptureActionNotFoundError,
    [ErrorCode.E_CAPTURE_ARGUMENT.code]: CaptureArgumentError,
    [ErrorCode.E_CAPTURE_OPEN.code]: CaptureOpenError,
    [ErrorCode.E_CAPTURE_FILTER.code]: CaptureFilterError
}

/**
 * Rebuild a capture error from a pipe RESPONSE_ERR payload. Errors cross the host-process boundary as
 * {message, errno, code}; map a known code back to its NetKittyError subclass so the main process can
 * catch it as one. An unknown or absent code falls back to a plain Error carrying the same errno/code.
 */
export function CaptureErrorFromPayload(payload: {message?: string, errno?: number, code?: string}): Error {
    const ErrorClass: (new (message?: string) => NetKittyError) | undefined = payload.code ? CAPTURE_ERROR_BY_CODE[payload.code] : undefined
    if (ErrorClass) return new ErrorClass(payload.message)
    const error: NodeJS.ErrnoException = new Error(payload.message)
    if (payload.errno !== undefined) error.errno = payload.errno
    if (payload.code !== undefined) error.code = payload.code
    return error
}
