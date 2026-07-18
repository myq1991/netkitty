/** Which pass a reducer update belongs to: replaying the already-indexed backlog, or the live tail. */
export type AnalysisPhase = 'replay' | 'live'
