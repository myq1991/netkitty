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
     * Whether to avoid writing captured packets to temporary pcap file
     */
    bypassFilesystem?: boolean
}
