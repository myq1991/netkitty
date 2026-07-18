import {CodecDecodeResult} from '@netkitty/codec'
import {IIndexStore} from '../interfaces/IIndexStore'
import {FrameIndexRecord} from '../types/FrameIndexRecord'
import {ConversationFlow, canonicalConversationKey, flowOf, hash32, topProtocolOf} from './ConversationKey'

/**
 * Turns a frame's decoded layers + capture metadata into a columnar index record, maintaining the two
 * small side dictionaries the numeric columns reference: protocol name↔id and conversation hash→key.
 * Both are per-protocol / per-conversation sized (far smaller than the frame count), so they stay in
 * memory while the bulk per-frame data lives in the TypedArray columns. conversationHash 0 is reserved
 * for frames with no derivable n-tuple.
 */
export class FrameIndexer {

    readonly #store: IIndexStore

    readonly #protocolIds: Map<string, number> = new Map<string, number>()

    readonly #protocolNames: string[] = []

    readonly #conversationKeys: Map<number, string> = new Map<number, string>()

    constructor(store: IIndexStore) {
        this.#store = store
    }

    public add(layers: CodecDecodeResult[], fileOffset: number, capturedLength: number, originalLength: number, timestamp: number): number {
        const flow: ConversationFlow | null = flowOf(layers)
        const key: string | null = flow ? canonicalConversationKey(flow) : null
        const conversationHash: number = key !== null ? hash32(key) : 0
        if (key !== null && !this.#conversationKeys.has(conversationHash)) this.#conversationKeys.set(conversationHash, key)
        const record: FrameIndexRecord = {
            index: -1,
            fileOffset: fileOffset,
            capturedLength: capturedLength,
            originalLength: originalLength,
            timestamp: timestamp,
            protocolId: this.#protocolId(topProtocolOf(layers)),
            conversationHash: conversationHash
        }
        return this.#store.append(record)
    }

    public protocolName(id: number): string {
        return id >= 0 && id < this.#protocolNames.length ? this.#protocolNames[id] : 'unknown'
    }

    public conversationKey(hash: number): string | null {
        const key: string | undefined = this.#conversationKeys.get(hash)
        return key !== undefined ? key : null
    }

    #protocolId(name: string): number {
        const existing: number | undefined = this.#protocolIds.get(name)
        if (existing !== undefined) return existing
        const id: number = this.#protocolNames.length
        this.#protocolIds.set(name, id)
        this.#protocolNames.push(name)
        return id
    }
}
