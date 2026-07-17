/**
 * Cross-packet flow analysis — a read-only subsystem layered above the codec. Consumes decoded
 * packets (plus capture timestamps) and groups them into conversations and endpoints.
 */
export {FlowAnalyzer} from './lib/analysis/FlowAnalyzer'
export type {AnalysisPacket, Conversation, Endpoint, FlowAnalysis} from './lib/analysis/FlowAnalyzer'
