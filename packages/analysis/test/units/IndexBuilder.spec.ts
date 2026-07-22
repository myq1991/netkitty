import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync} from 'node:fs'
import {Codec, CodecDecodeResult} from '@netkitty/codec'
import {IPcapPacketInfo, PcapParserCore} from '@netkitty/pcap-core'
import {NodeFileReadBackend} from '../../src/backends/NodeFileReadBackend'
import {ColumnarIndexStore} from '../../src/stores/ColumnarIndexStore'
import {FrameIndexer} from '../../src/indexer/FrameIndexer'
import {PcapIndexBuilder} from '../../src/indexer/PcapIndexBuilder'
import {canonicalConversationKey, flowOf, topProtocolOf} from '../../src/indexer/ConversationKey'
import {FrameIndexRecord} from '../../src/types/FrameIndexRecord'
import {FixtureCapturePath} from '../lib/Fixtures'

type ExpectedFrame = {fileOffset: number, packetLength: number, timestamp: number, topProtocol: string, conversationKey: string | null}

//Reference: parse the whole file in memory, decode each frame, and compute what the columnar index
//should end up holding. Uses the same codec + helpers, so this validates the builder's plumbing
//(stream → parser → decode → indexer → store), which is exactly what step 4a-2 adds.
async function directParse(buffer: Buffer): Promise<ExpectedFrame[]> {
    const codec: Codec = new Codec()
    const frames: {info: IPcapPacketInfo, data: Buffer}[] = []
    let last: Buffer = Buffer.alloc(0)
    const parser: PcapParserCore = new PcapParserCore({
        onPacketData: (data: Buffer): void => {last = Buffer.from(data)},
        onPacket: (info: IPcapPacketInfo): void => {frames.push({info: info, data: last})}
    })
    parser.write(buffer)
    parser.end()
    const out: ExpectedFrame[] = []
    for (const frame of frames) {
        const layers: CodecDecodeResult[] = await codec.decode(frame.data)
        const key: string | null = flowOf(layers) ? canonicalConversationKey(flowOf(layers)!) : null
        out.push({
            fileOffset: frame.info.packetOffset,
            packetLength: frame.info.packetLength,
            timestamp: frame.info.seconds + frame.info.microseconds / 1_000_000,
            topProtocol: topProtocolOf(layers),
            conversationKey: key
        })
    }
    return out
}

async function assertFixtureRoundTrips(name: string): Promise<void> {
    const expected: ExpectedFrame[] = await directParse(readFileSync(FixtureCapturePath(name)))
    const store: ColumnarIndexStore = new ColumnarIndexStore(16)
    const indexer: FrameIndexer = new FrameIndexer(store)
    const builder: PcapIndexBuilder = new PcapIndexBuilder(indexer, new Codec())
    //Tiny chunk size forces multi-chunk reads and cross-chunk frame boundaries, stressing the drain.
    const count: number = await builder.build(new NodeFileReadBackend(FixtureCapturePath(name), 64))
    assert.strictEqual(count, expected.length, `${name}: frame count`)
    assert.ok(count > 0, `${name}: has frames`)
    for (let i: number = 0; i < expected.length; i++) {
        const record: FrameIndexRecord = store.get(i)!
        assert.strictEqual(record.fileOffset, expected[i].fileOffset, `${name} frame ${i}: fileOffset`)
        assert.strictEqual(record.capturedLength, expected[i].packetLength, `${name} frame ${i}: length`)
        assert.strictEqual(record.timestamp, expected[i].timestamp, `${name} frame ${i}: timestamp`)
        assert.strictEqual(indexer.protocolName(record.protocolId), expected[i].topProtocol, `${name} frame ${i}: protocol`)
        assert.strictEqual(indexer.conversationKey(record.conversationHash), expected[i].conversationKey, `${name} frame ${i}: conversation`)
    }
}

test('index builder: classic pcap (iec104) reproduces a direct parse frame-by-frame', async (): Promise<void> => {
    await assertFixtureRoundTrips('iec104.pcap')
})

test('index builder: pcapng (tcp-1) reproduces a direct parse frame-by-frame', async (): Promise<void> => {
    await assertFixtureRoundTrips('tcp-1.pcapng')
})

test('index builder: pcapng (ipv4-one) reproduces a direct parse frame-by-frame', async (): Promise<void> => {
    await assertFixtureRoundTrips('ipv4-one.pcapng')
})

test('index builder: onProgress advances to the full file size', async (): Promise<void> => {
    const path: string = FixtureCapturePath('iec104.pcap')
    const store: ColumnarIndexStore = new ColumnarIndexStore(16)
    const builder: PcapIndexBuilder = new PcapIndexBuilder(new FrameIndexer(store), new Codec())
    let lastBytes: number = 0
    let lastTotal: number = 0
    await builder.build(new NodeFileReadBackend(path, 128), {
        onProgress: (bytesRead: number, totalBytes: number): void => {lastBytes = bytesRead; lastTotal = totalBytes}
    })
    assert.strictEqual(lastBytes, lastTotal)
    assert.strictEqual(lastTotal, readFileSync(path).length)
})
