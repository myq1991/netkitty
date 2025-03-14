import {GetCaptureTemporaryDirectory} from './GetCaptureTemporaryDirectory'
import path from 'node:path'

/**
 * Get device capture temporary filename
 * @param device
 * @constructor
 */
export function GetDeviceCaptureTemporaryFilename(device: string): string {
    const cacheDir: string = GetCaptureTemporaryDirectory()
    return path.resolve(cacheDir, `${Buffer.from(device).toString('hex')}.pcap`)
}
