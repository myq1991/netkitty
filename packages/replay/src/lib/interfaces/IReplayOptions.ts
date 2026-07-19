/**
 * Pacing mode.
 * - `multiplier`: reproduce the recorded inter-frame timing, scaled by `rate` (1 = original speed,
 *   2 = twice as fast, 0.5 = half). This is accurate replay.
 * - `topspeed`: send as fast as the interface accepts (no pacing). Traffic generation.
 * - `mbps`: hold an average throughput of `rate` megabits per second.
 * - `pps`: hold an average rate of `rate` packets per second.
 */
export type ReplayMode = 'multiplier' | 'topspeed' | 'mbps' | 'pps'

/**
 * Timing precision for paced modes.
 * - `auto` (default): sleep the bulk of each gap, busy-spin the final ~250µs for accuracy.
 * - `sleep`: always sleep (lower CPU, coarser).
 * - `spin`: busy-spin more aggressively (highest accuracy, highest CPU).
 */
export type ReplayPrecision = 'auto' | 'sleep' | 'spin'

export interface IReplayOptions {
    /** Interface to transmit on (name, e.g. `en0` / `eth0` / an Npcap device string). */
    device: string
    /** Pacing mode. Default `multiplier`. */
    mode?: ReplayMode
    /** Rate for the mode: multiplier factor / megabits-per-second / packets-per-second. Default 1. */
    rate?: number
    /** Number of passes over the frame set. Default 1. */
    loop?: number
    /** Loop forever (overrides `loop`). Default false. */
    infinite?: boolean
    /** Pause between passes, milliseconds. Default 0. */
    loopDelayMs?: number
    /** Stop after this many frames have been sent (0 = no limit). Default 0. */
    limit?: number
    /** Clamp any single inter-frame wait to at most this many ms (0 = no clamp). Useful to skip long idle gaps. */
    maxSleepMs?: number
    /** Timing precision for paced modes. Default `auto`. */
    precision?: ReplayPrecision
    /**
     * Request real-time scheduling for the send thread (POSIX SCHED_FIFO / Windows TIME_CRITICAL).
     * Needs elevated privileges to take effect and can monopolise a CPU core — leave off unless you
     * need the tightest possible pacing. Default false (a safe priority boost is always applied).
     */
    realtime?: boolean
    /**
     * Verify the device exists (via @netkitty/iface, if installed) before starting, throwing a clear
     * error listing available interfaces if not. Default true; set false to skip the check.
     */
    validateDevice?: boolean
}
