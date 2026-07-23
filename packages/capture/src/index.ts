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
export * from './errors'
