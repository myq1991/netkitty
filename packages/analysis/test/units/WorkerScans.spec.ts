import {test} from 'node:test'
import assert from 'node:assert'
import {Analysis} from '../../src/lib/streaming/Analysis'
import {ConversationsReducer, ConversationSummary} from '../../src/lib/streaming/reducers/ConversationsReducer'
import {EndpointsReducer, EndpointSummary} from '../../src/lib/streaming/reducers/EndpointsReducer'
import {FixtureCapturePath} from '../lib/Fixtures'

//The worker-side column scan must produce byte-identical results to the main-thread reducer — it just
//derives them from the index columns (five-tuple/length/timestamp/direction) instead of the layers.
test('worker scans: conversations() equals attaching a ConversationsReducer', async (): Promise<void> => {
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('iec104.pcap'))
    const viaWorker: ConversationSummary[] = await analysis.conversations()
    const reducer: ConversationsReducer = new ConversationsReducer()
    await analysis.attachReducer(reducer)
    const viaReducer: ConversationSummary[] = reducer.result()
    assert.strictEqual(viaWorker.length, viaReducer.length)
    assert.ok(viaWorker.length > 0)
    for (const want of viaReducer) {
        const got: ConversationSummary | undefined = viaWorker.find((c: ConversationSummary): boolean => c.protocol === want.protocol && c.endpointA === want.endpointA && c.endpointB === want.endpointB)
        assert.ok(got, `conversation ${want.endpointA}↔${want.endpointB}`)
        assert.deepStrictEqual(got, want)
    }
    await analysis.close()
})

test('worker scans: endpoints() equals attaching an EndpointsReducer', async (): Promise<void> => {
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('iec104.pcap'))
    const viaWorker: EndpointSummary[] = await analysis.endpoints()
    const reducer: EndpointsReducer = new EndpointsReducer()
    await analysis.attachReducer(reducer)
    const viaReducer: EndpointSummary[] = reducer.result()
    assert.strictEqual(viaWorker.length, viaReducer.length)
    assert.ok(viaWorker.length > 0)
    for (const want of viaReducer) {
        const got: EndpointSummary | undefined = viaWorker.find((e: EndpointSummary): boolean => e.address === want.address)
        assert.ok(got, `endpoint ${want.address}`)
        assert.deepStrictEqual(got, want)
    }
    await analysis.close()
})
