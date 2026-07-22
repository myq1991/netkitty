import {Replay} from './Replay'
import {loadFrames} from './loadFrames'
import {IReplayOptions} from './interfaces/IReplayOptions'

/**
 * Convenience: load a capture file and build a {@link Replay} pre-filled with its frames. The returned
 * instance is not started — attach `progress`/`done`/`error` listeners first, then call `start()`.
 *
 * ```ts
 * const replay = await replayFile('capture.pcap', {device: 'en0'})
 * replay.on('done', (s) => console.log(s))
 * replay.start()
 * ```
 */
export async function replayFile(filename: string, options: IReplayOptions): Promise<Replay> {
    const replay: Replay = new Replay(options)
    replay.addFrames(await loadFrames(filename))
    return replay
}
