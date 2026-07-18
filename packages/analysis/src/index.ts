/**
 * Cross-packet flow analysis — a read-only subsystem layered above the codec. Consumes decoded
 * packets (plus capture timestamps) and groups them into conversations and endpoints.
 */
export {FlowAnalyzer} from './lib/analysis/FlowAnalyzer'
export type {AnalysisPacket, Conversation, Endpoint, FlowAnalysis} from './lib/analysis/FlowAnalyzer'
export {TcpStreamAnalyzer} from './lib/analysis/TcpStreamAnalyzer'
export type {RttSample, TcpAnalysis, TcpStreamDiagnostic} from './lib/analysis/TcpStreamAnalyzer'

/**
 * Streaming capture-file analysis (v1, in progress) — the Analysis facade plus pluggable reducers and
 * the backend seams. Signatures are frozen here; implementations land incrementally.
 */
export {Analysis} from './lib/streaming/Analysis'
export type {AnalysisOptions} from './lib/streaming/types/AnalysisOptions'
export type {AnalysisSource} from './lib/streaming/types/AnalysisSource'
export type {AnalysisEvents} from './lib/streaming/types/AnalysisEvents'
export type {AnalysisPhase} from './lib/streaming/types/AnalysisPhase'
export type {UpdateContext} from './lib/streaming/types/UpdateContext'
export type {Frame} from './lib/streaming/types/Frame'
export type {FrameRow} from './lib/streaming/types/FrameRow'
export type {FrameIndexRecord} from './lib/streaming/types/FrameIndexRecord'
export type {IAnalysisReducer} from './lib/streaming/interfaces/IAnalysisReducer'
export type {IReadBackend} from './lib/streaming/interfaces/IReadBackend'
export type {IWorkerChannel} from './lib/streaming/interfaces/IWorkerChannel'
export type {IIndexStore} from './lib/streaming/interfaces/IIndexStore'

/**
 * Built-in reducers (exported, not baked into Analysis) — attach them for Wireshark-style stats.
 */
export {ConversationsReducer} from './lib/streaming/reducers/ConversationsReducer'
export type {ConversationSummary} from './lib/streaming/reducers/ConversationsReducer'
export {EndpointsReducer} from './lib/streaming/reducers/EndpointsReducer'
export type {EndpointSummary} from './lib/streaming/reducers/EndpointsReducer'
export {TcpStreamReducer} from './lib/streaming/reducers/TcpStreamReducer'
export {reduceReducer, groupByReducer} from './lib/streaming/reducers/ReducerFactories'
export {parseFilter, matchesFilter} from './lib/streaming/filter/FilterExpression'
export type {FilterExpression, FilterPredicate} from './lib/streaming/filter/FilterExpression'
