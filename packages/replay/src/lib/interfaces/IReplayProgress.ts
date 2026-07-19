/**
 * Progress/completion snapshot delivered on the `progress` and `done` events.
 */
export interface IReplayProgress {
    /** Frames successfully put on the wire so far. */
    sent: number
    /** Bytes successfully sent so far. */
    bytes: number
    /** Frames the backend refused (send error). */
    failed: number
    /** Wall-clock elapsed since the run started, milliseconds. */
    elapsedMs: number
    /** Current pass index (0-based). */
    loop: number
    /** Achieved rate, packets per second (over the whole run so far). */
    pps: number
    /** Achieved throughput, megabits per second (over the whole run so far). */
    mbps: number
    /** The send backend actually in use: `pf_packet` (Linux), `bpf` (BSD/macOS) or `pcap` (fallback / Windows). */
    backend: string
}
