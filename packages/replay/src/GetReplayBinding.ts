import {GetBinding} from './GetBinding'
import path from 'node:path'
import {existsSync} from 'node:fs'

//The native class (constructed with an options object, driven with addFrames/start/stop).
export interface INativeReplay {
    addFrames(frames: {data: Buffer, seconds?: number, nanoseconds?: number}[]): void
    start(): void
    stop(): void
    emit?: (event: string, payload: unknown) => void
}

export interface IReplayBinding {
    NetKittyReplay: new (options: Record<string, unknown>) => INativeReplay
    //On Windows this loads wpcap.dll (Npcap) and returns false if Npcap is not installed; POSIX: always true.
    Prepare(): boolean
}

//Walk up from this module to find bindings/netkitty_replay.node — robust whether loaded from dist/ or
//dist-test/ (whose extra rootDir level would break a fixed relative path).
function resolveBindingPath(): string {
    let dir: string = __dirname
    for (let i: number = 0; i < 6; i++) {
        const candidate: string = path.join(dir, 'bindings', 'netkitty_replay.node')
        if (existsSync(candidate)) return candidate
        dir = path.dirname(dir)
    }
    return path.resolve(__dirname, '../../bindings/netkitty_replay.node')
}

let binding: IReplayBinding | null = null

export function GetReplayBinding(): IReplayBinding {
    if (!binding) {
        binding = GetBinding(resolveBindingPath()) as IReplayBinding
    }
    return binding
}
