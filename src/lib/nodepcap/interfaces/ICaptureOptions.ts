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
     * Custom capture worker module path
     */
    workerModule?: string

    /**
     * The temporary folder path for storing captured pcap files
     */
    tmpDir?: string
}
