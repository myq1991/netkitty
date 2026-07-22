import {FrameRow} from './FrameRow'

/** Event map for the Analysis facade: newly indexed frame, indexing progress, completion, error. */
export type AnalysisEvents = {
    frame: (row: FrameRow) => void
    progress: (done: number, total: number) => void
    complete: () => void
    error: (error: Error) => void
}
