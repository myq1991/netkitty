import {Frame} from '../types/Frame'
import {UpdateContext} from '../types/UpdateContext'
import {IAnalysisReducer} from '../interfaces/IAnalysisReducer'
import {ConversationFlow, flowOf} from '../indexer/ConversationKey'

/** Per-endpoint traffic totals, direction-aware (tx = seen as source, rx = seen as destination). */
export type EndpointSummary = {
    address: string
    packets: number
    bytes: number
    txPackets: number
    txBytes: number
    rxPackets: number
    rxBytes: number
}

/**
 * Rolling per-endpoint totals: every frame credits its source (tx) and destination (rx). result() is
 * a snapshot; reset() clears it. Mirrors FlowAnalyzer's endpoint accounting.
 */
export class EndpointsReducer implements IAnalysisReducer<EndpointSummary[]> {

    public readonly needs: string[] = ['eth', 'ipv4', 'ipv6', 'tcp', 'udp', 'arp']

    readonly #endpoints: Map<string, EndpointSummary> = new Map<string, EndpointSummary>()

    public update(frame: Frame, context: UpdateContext): void {
        void context
        const flow: ConversationFlow | null = flowOf(frame.layers)
        if (!flow) return
        this.#account(flow.source, frame.length, true)
        this.#account(flow.destination, frame.length, false)
    }

    public result(): EndpointSummary[] {
        return [...this.#endpoints.values()]
    }

    public reset(): void {
        this.#endpoints.clear()
    }

    #account(address: string, length: number, isSource: boolean): void {
        let endpoint: EndpointSummary | undefined = this.#endpoints.get(address)
        if (!endpoint) {
            endpoint = {address: address, packets: 0, bytes: 0, txPackets: 0, txBytes: 0, rxPackets: 0, rxBytes: 0}
            this.#endpoints.set(address, endpoint)
        }
        endpoint.packets++
        endpoint.bytes += length
        if (isSource) {
            endpoint.txPackets++
            endpoint.txBytes += length
        } else {
            endpoint.rxPackets++
            endpoint.rxBytes += length
        }
    }
}
