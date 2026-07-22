import {AnalysisPhase} from './AnalysisPhase'

/** Context handed to a reducer alongside each frame: position in the stream and which pass it is. */
export type UpdateContext = {
    index: number
    total: number
    phase: AnalysisPhase
}
