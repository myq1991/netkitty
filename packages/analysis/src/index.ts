/**
 * Streaming capture-file analysis — the Analysis facade over a single worker, pluggable reducers, a
 * display filter, and the pluggable backend seams. node (worker_threads) and browser (Web Worker)
 * share one environment-agnostic API, verified field-for-field in both.
 */
export {Analysis} from './Analysis'
export type {AnalysisOptions} from './types/AnalysisOptions'
export type {AnalysisSource} from './types/AnalysisSource'
export type {AnalysisEvents} from './types/AnalysisEvents'
export type {AnalysisPhase} from './types/AnalysisPhase'
export type {UpdateContext} from './types/UpdateContext'
export type {Frame} from './types/Frame'
export type {FrameRow} from './types/FrameRow'
export type {FrameIndexRecord} from './types/FrameIndexRecord'
export type {IAnalysisReducer} from './interfaces/IAnalysisReducer'
export type {IReadBackend} from './interfaces/IReadBackend'
export type {IWorkerChannel} from './interfaces/IWorkerChannel'
export type {IIndexStore} from './interfaces/IIndexStore'

/**
 * Built-in reducers (exported, not baked into Analysis) — attach them for Wireshark-style stats.
 */
export {ConversationsReducer} from './reducers/ConversationsReducer'
export type {ConversationSummary} from './reducers/ConversationsReducer'
export {EndpointsReducer} from './reducers/EndpointsReducer'
export type {EndpointSummary} from './reducers/EndpointsReducer'
export {TcpStreamReducer} from './reducers/TcpStreamReducer'
export type {RttSample, TcpStreamDiagnostic} from './reducers/TcpStreamReducer'
export {reduceReducer, groupByReducer} from './reducers/ReducerFactories'
export {parseFilter, matchesFilter, matchesIndexed, indexableEval} from './filter/FilterExpression'
export type {FilterExpression, FilterPredicate} from './filter/FilterExpression'

/**
 * Error classes (all extend NetKittyError)
 */
export {AnalysisStateError} from './errors/AnalysisStateError'
