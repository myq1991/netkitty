import {Frame} from '../types/Frame'
import {UpdateContext} from '../types/UpdateContext'
import {IAnalysisReducer} from '../interfaces/IAnalysisReducer'
import {ConversationFlow, flowOf} from '../indexer/ConversationKey'

/**
 * A bidirectional conversation summary. Same shape as FlowAnalyzer's Conversation, except the full
 * packetIndices array is replaced by firstIndex/lastIndex — the member frame list is recovered from
 * the index layer (filter/range) instead of held per-conversation, so state stays bounded.
 */
export type ConversationSummary = {
    protocol: string
    endpointA: string
    endpointB: string
    packets: number
    bytes: number
    packetsAToB: number
    packetsBToA: number
    firstTimestamp: number
    lastTimestamp: number
    firstIndex: number
    lastIndex: number
}

/**
 * Rolling conversation table: groups frames direction-independently by n-tuple, tallying packets,
 * bytes, per-direction counts and time/index spans. result() is a snapshot at any point; reset()
 * clears it. Mirrors FlowAnalyzer so streaming and batch agree.
 */
export class ConversationsReducer implements IAnalysisReducer<ConversationSummary[]> {

    public readonly needs: string[] = ['eth', 'ipv4', 'ipv6', 'tcp', 'udp', 'arp']

    //Only the five-tuple — replay can feed frames synthesized from the index columns (no re-decode).
    public readonly indexOnly: boolean = true

    readonly #conversations: Map<string, ConversationSummary> = new Map<string, ConversationSummary>()

    public update(frame: Frame, context: UpdateContext): void {
        void context
        const flow: ConversationFlow | null = flowOf(frame.layers)
        if (!flow) return
        const forward: boolean = flow.source <= flow.destination
        const endpointA: string = forward ? flow.source : flow.destination
        const endpointB: string = forward ? flow.destination : flow.source
        const key: string = `${flow.protocol}|${endpointA}|${endpointB}`
        let conversation: ConversationSummary | undefined = this.#conversations.get(key)
        if (!conversation) {
            conversation = {
                protocol: flow.protocol,
                endpointA: endpointA,
                endpointB: endpointB,
                packets: 0,
                bytes: 0,
                packetsAToB: 0,
                packetsBToA: 0,
                firstTimestamp: frame.timestamp,
                lastTimestamp: frame.timestamp,
                firstIndex: frame.index,
                lastIndex: frame.index
            }
            this.#conversations.set(key, conversation)
        }
        conversation.packets++
        conversation.bytes += frame.length
        if (flow.source === endpointA) conversation.packetsAToB++
        else conversation.packetsBToA++
        if (frame.timestamp < conversation.firstTimestamp) conversation.firstTimestamp = frame.timestamp
        if (frame.timestamp > conversation.lastTimestamp) conversation.lastTimestamp = frame.timestamp
        if (frame.index < conversation.firstIndex) conversation.firstIndex = frame.index
        if (frame.index > conversation.lastIndex) conversation.lastIndex = frame.index
    }

    public result(): ConversationSummary[] {
        return [...this.#conversations.values()]
    }

    public reset(): void {
        this.#conversations.clear()
    }
}
