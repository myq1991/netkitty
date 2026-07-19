/**
 * Controls what each captured packet delivers back to the main process:
 * - `full` (default): metadata plus the raw packet bytes — backwards compatible; emits `rawPacket`.
 * - `metadata`: metadata only (index/offsets/timestamp/length); the bytes stay in the on-disk file,
 *   skipping the per-packet base64 encoding and the largest part of the IPC payload.
 */
export type CaptureEmitMode = 'metadata' | 'full'

export interface ICaptureOptions {
    /**
     * Ethernet interface
     */
    device: string
    /**
     * Capture filter
     */
    filter?: string
    /**
     * What to deliver per captured packet. Default `full`.
     */
    emit?: CaptureEmitMode
    /**
     * Custom capture worker module path
     */
    workerModule?: string

    /**
     * The temporary folder path for storing captured pcap files
     */
    tmpDir?: string

    /**
     * Temporary filename
     */
    temporaryFilename?:string
}
