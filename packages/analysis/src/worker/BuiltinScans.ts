import {IIndexStore} from '../interfaces/IIndexStore'
import {FrameIndexRecord} from '../types/FrameIndexRecord'
import {ConversationSummary} from '../reducers/ConversationsReducer'
import {EndpointSummary} from '../reducers/EndpointsReducer'

/**
 * Built-in Conversations/Endpoints computed by scanning the index columns directly — no re-decode, no
 * cross-thread frame transfer. Everything these reducers need (the five-tuple via keyOf, captured
 * length, timestamp, and the direction bit) is already in the index. Runs inside the worker; only the
 * small result table crosses back to the main thread, so the main thread stays free. Results are
 * identical to ConversationsReducer/EndpointsReducer, just derived from columns instead of layers.
 *
 * Hot loops key their caches on the numeric conversationHash (fast Map) and resolve/parse the string
 * key only once per conversation, so cost is ~one Map lookup + a few field bumps per frame.
 */
export function computeConversations(store: IIndexStore, keyOf: (conversationHash: number) => string | null): ConversationSummary[] {
    const byHash: Map<number, ConversationSummary | null> = new Map<number, ConversationSummary | null>()
    const first: number = store.firstIndex()
    const end: number = first + store.count()
    for (let i: number = first; i < end; i++) {
        const record: FrameIndexRecord | null = store.get(i)
        if (!record) continue
        let conversation: ConversationSummary | null | undefined = byHash.get(record.conversationHash)
        if (conversation === undefined) {
            const key: string | null = keyOf(record.conversationHash)
            if (key === null) {byHash.set(record.conversationHash, null); continue}
            const bar1: number = key.indexOf('|')
            const bar2: number = key.indexOf('|', bar1 + 1)
            conversation = {
                protocol: key.slice(0, bar1),
                endpointA: key.slice(bar1 + 1, bar2),
                endpointB: key.slice(bar2 + 1),
                packets: 0,
                bytes: 0,
                packetsAToB: 0,
                packetsBToA: 0,
                firstTimestamp: record.timestamp,
                lastTimestamp: record.timestamp,
                firstIndex: record.index,
                lastIndex: record.index
            }
            byHash.set(record.conversationHash, conversation)
        }
        if (conversation === null) continue
        conversation.packets++
        conversation.bytes += record.capturedLength
        if (record.directionForward) conversation.packetsAToB++
        else conversation.packetsBToA++
        if (record.timestamp < conversation.firstTimestamp) conversation.firstTimestamp = record.timestamp
        if (record.timestamp > conversation.lastTimestamp) conversation.lastTimestamp = record.timestamp
        if (record.index < conversation.firstIndex) conversation.firstIndex = record.index
        if (record.index > conversation.lastIndex) conversation.lastIndex = record.index
    }
    const out: ConversationSummary[] = []
    for (const conversation of byHash.values()) if (conversation !== null) out.push(conversation)
    return out
}

type EndpointPair = {a: EndpointSummary, b: EndpointSummary}

/**
 * Built-in Endpoints table, computed by scanning the index columns directly (no re-decode). Groups
 * every frame's two endpoints, accumulating per-address total/tx/rx packet and byte counts from the
 * direction bit. Result matches EndpointsReducer.
 * @param store index columns to scan.
 * @param keyOf resolves a conversation hash to its `protocol|endpointA|endpointB` key, or null when unknown.
 * @returns one summary per distinct endpoint address seen.
 */
export function computeEndpoints(store: IIndexStore, keyOf: (conversationHash: number) => string | null): EndpointSummary[] {
    const endpoints: Map<string, EndpointSummary> = new Map<string, EndpointSummary>()
    const byHash: Map<number, EndpointPair | null> = new Map<number, EndpointPair | null>()
    const first: number = store.firstIndex()
    const end: number = first + store.count()
    for (let i: number = first; i < end; i++) {
        const record: FrameIndexRecord | null = store.get(i)
        if (!record) continue
        let pair: EndpointPair | null | undefined = byHash.get(record.conversationHash)
        if (pair === undefined) {
            const key: string | null = keyOf(record.conversationHash)
            if (key === null) {byHash.set(record.conversationHash, null); continue}
            const bar1: number = key.indexOf('|')
            const bar2: number = key.indexOf('|', bar1 + 1)
            pair = {a: getOrCreate(endpoints, key.slice(bar1 + 1, bar2)), b: getOrCreate(endpoints, key.slice(bar2 + 1))}
            byHash.set(record.conversationHash, pair)
        }
        if (pair === null) continue
        const source: EndpointSummary = record.directionForward ? pair.a : pair.b
        const destination: EndpointSummary = record.directionForward ? pair.b : pair.a
        source.packets++
        source.bytes += record.capturedLength
        source.txPackets++
        source.txBytes += record.capturedLength
        destination.packets++
        destination.bytes += record.capturedLength
        destination.rxPackets++
        destination.rxBytes += record.capturedLength
    }
    return [...endpoints.values()]
}

function getOrCreate(endpoints: Map<string, EndpointSummary>, address: string): EndpointSummary {
    let endpoint: EndpointSummary | undefined = endpoints.get(address)
    if (!endpoint) {
        endpoint = {address: address, packets: 0, bytes: 0, txPackets: 0, txBytes: 0, rxPackets: 0, rxBytes: 0}
        endpoints.set(address, endpoint)
    }
    return endpoint
}
