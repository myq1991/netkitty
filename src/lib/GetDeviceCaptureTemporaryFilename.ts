import {GetCaptureTemporaryDirectory} from './GetCaptureTemporaryDirectory'
import path from 'node:path'

/**
 * Get device capture temporary filename
 * @param device
 * @param tmpDir
 * @constructor
 */
export function GetDeviceCaptureTemporaryFilename(device: string, tmpDir: string): string {
    const cacheDir: string = GetCaptureTemporaryDirectory(tmpDir)
    return path.resolve(cacheDir, `${Buffer.from(device).toString('hex')}.pcap`)
}
