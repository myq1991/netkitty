/**
 * Fetch network interface
 */
export {GetNetworkInterfaces} from './capture/GetNetworkInterfaces'
/**
 * Network packet capture
 */
export {Capture} from './capture/Capture'
/**
 * Types
 */
export {type INetworkInterface} from './capture/interfaces/INetworkInterface'
export {type ICaptureOptions, type CaptureEmitMode} from './capture/interfaces/ICaptureOptions'
/**
 * Error classes (all extend NetKittyError)
 */
export {CaptureDeviceNotFoundError} from './errors/CaptureDeviceNotFoundError'
export {CaptureNpcapLoadError} from './errors/CaptureNpcapLoadError'
export {CaptureSocketDownError} from './errors/CaptureSocketDownError'
export {CaptureUnknownPipeMessageTypeError} from './errors/CaptureUnknownPipeMessageTypeError'
export {CaptureActionNotFoundError} from './errors/CaptureActionNotFoundError'
export {CaptureArgumentError} from './errors/CaptureArgumentError'
export {CaptureOpenError} from './errors/CaptureOpenError'
export {CaptureFilterError} from './errors/CaptureFilterError'
