/**
 * One frame to transmit. `data` is the complete Layer-2 frame (sent verbatim). The timestamp is only
 * consulted in `multiplier` mode, where inter-frame gaps are reproduced from it — for `topspeed`,
 * `mbps` and `pps` it is ignored, so raw traffic generators can omit it.
 */
export interface IReplayFrame {
    data: Buffer
    seconds?: number
    nanoseconds?: number
}
