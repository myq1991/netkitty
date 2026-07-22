import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync} from 'node:fs'
import {Codec, CodecDecodeResult} from '@netkitty/codec'
import {IPcapPacketInfo, PcapParserCore} from '@netkitty/pcap-core'
import {Analysis} from '../../src/Analysis'
import {Frame} from '../../src/types/Frame'
import {UpdateContext} from '../../src/types/UpdateContext'
import {ConversationSummary, ConversationsReducer} from '../../src/reducers/ConversationsReducer'
import {EndpointSummary, EndpointsReducer} from '../../src/reducers/EndpointsReducer'
import {FixtureCapturePath} from '../lib/Fixtures'

const CTX: UpdateContext = {index: 0, total: 0, phase: 'replay'}

//Reference: run the reducer directly over a main-thread parse of the same file.
async function referenceFrames(name: string): Promise<Frame[]> {
    const codec: Codec = new Codec()
    const raw: {info: IPcapPacketInfo, data: Buffer}[] = []
    let last: Buffer = Buffer.alloc(0)
    const parser: PcapParserCore = new PcapParserCore({
        onPacketData: (data: Buffer): void => {last = Buffer.from(data)},
        onPacket: (info: IPcapPacketInfo): void => {raw.push({info: info, data: last})}
    })
    parser.write(readFileSync(FixtureCapturePath(name)))
    parser.end()
    const frames: Frame[] = []
    for (let i: number = 0; i < raw.length; i++) {
        const layers: CodecDecodeResult[] = await codec.decode(raw[i].data)
        frames.push({
            index: i,
            timestamp: raw[i].info.seconds + raw[i].info.microseconds / 1_000_000,
            length: raw[i].info.packetLength,
            capturedLength: raw[i].info.packetLength,
            topProtocol: '',
            conversationKey: null,
            info: '',
            layers: JSON.parse(JSON.stringify(layers))
        })
    }
    return frames
}

test('attachReducer: replays every indexed frame into a Conversations reducer, matching a direct run', async (): Promise<void> => {
    const reference: ConversationsReducer = new ConversationsReducer()
    for (const frame of await referenceFrames('tcp-1.pcapng')) reference.update(frame, CTX)
    const expected: ConversationSummary[] = reference.result()

    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('tcp-1.pcapng'))
    const conversations: ConversationsReducer = new ConversationsReducer()
    await analysis.attachReducer(conversations)
    const got: ConversationSummary[] = conversations.result()

    assert.strictEqual(got.length, expected.length)
    assert.ok(got.length > 0, 'has conversations')
    for (const want of expected) {
        const found: ConversationSummary | undefined = got.find((c: ConversationSummary): boolean => c.endpointA === want.endpointA && c.endpointB === want.endpointB)
        assert.ok(found, `conversation ${want.endpointA}↔${want.endpointB}`)
        assert.strictEqual(found!.packets, want.packets)
        assert.strictEqual(found!.bytes, want.bytes)
        assert.strictEqual(found!.firstIndex, want.firstIndex)
        assert.strictEqual(found!.lastIndex, want.lastIndex)
    }
    //Total packets across conversations equals the frame count (every IP/eth frame lands somewhere).
    const totalPackets: number = got.reduce((sum: number, c: ConversationSummary): number => sum + c.packets, 0)
    assert.strictEqual(totalPackets, analysis.frameCount())
    await analysis.close()
})

test('attachReducer: Endpoints reducer replay matches a direct run', async (): Promise<void> => {
    const reference: EndpointsReducer = new EndpointsReducer()
    for (const frame of await referenceFrames('iec104.pcap')) reference.update(frame, CTX)
    const expected: EndpointSummary[] = reference.result()

    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('iec104.pcap'))
    const endpoints: EndpointsReducer = new EndpointsReducer()
    await analysis.attachReducer(endpoints)
    const got: EndpointSummary[] = endpoints.result()

    assert.strictEqual(got.length, expected.length)
    for (const want of expected) {
        const found: EndpointSummary | undefined = got.find((e: EndpointSummary): boolean => e.address === want.address)
        assert.ok(found, `endpoint ${want.address}`)
        assert.strictEqual(found!.packets, want.packets)
        assert.strictEqual(found!.txBytes, want.txBytes)
        assert.strictEqual(found!.rxBytes, want.rxBytes)
    }
    await analysis.close()
})

test('attachReducer: indexOnly synthesis matches a decoding replay', async (): Promise<void> => {
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('iec104.pcap'))
    const synthesized: ConversationsReducer = new ConversationsReducer()          // indexOnly=true → columns
    await analysis.attachReducer(synthesized)
    const decoded: ConversationsReducer = new ConversationsReducer()
    ;(decoded as unknown as {indexOnly: boolean}).indexOnly = false                // force the decode path
    await analysis.attachReducer(decoded)
    const keyOf = (c: ConversationSummary): string => `${c.protocol}|${c.endpointA}|${c.endpointB}`
    const sorted = (arr: ConversationSummary[]): ConversationSummary[] => [...arr].sort((a: ConversationSummary, b: ConversationSummary): number => (keyOf(a) < keyOf(b) ? -1 : 1))
    assert.strictEqual(synthesized.result().length, decoded.result().length)
    assert.ok(synthesized.result().length > 0)
    assert.deepStrictEqual(sorted(synthesized.result()), sorted(decoded.result()))
    await analysis.close()
})

test('attachReducer: detachReducer drops the reference', async (): Promise<void> => {
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('tcp-1.pcapng'))
    const conversations: ConversationsReducer = new ConversationsReducer()
    await analysis.attachReducer(conversations)
    const before: number = conversations.result().length
    analysis.detachReducer(conversations)
    //Reducer keeps its own state after detach; detach only stops future feeding.
    assert.strictEqual(conversations.result().length, before)
    await analysis.close()
})
