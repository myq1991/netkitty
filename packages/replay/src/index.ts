/**
 * Packet replay and traffic generation over a native addon. Sends frames on the fastest backend the
 * platform offers (Linux PF_PACKET, BSD/macOS BPF, Windows Npcap), paced to reproduce recorded timing
 * or to hold a target rate. All transmission happens on a dedicated thread off the Node event loop.
 */
import {GetReplayBinding} from './lib/GetReplayBinding'

export {Replay} from './lib/Replay'
export {loadFrames} from './lib/loadFrames'
export {replayFile} from './lib/replayFile'
export type {IReplayOptions, ReplayMode, ReplayPrecision} from './lib/interfaces/IReplayOptions'
export type {IReplayFrame} from './lib/interfaces/IReplayFrame'
export type {IReplayProgress} from './lib/interfaces/IReplayProgress'

/**
 * Whether the pcap send path is available. On Windows this loads wpcap.dll and returns false when Npcap
 * is not installed (the native PF_PACKET/BPF backends on POSIX do not need it, so this is mainly a
 * Windows readiness probe). Never throws.
 */
export function isSendAvailable(): boolean {
    try {
        return GetReplayBinding().Prepare()
    } catch {
        return false
    }
}
