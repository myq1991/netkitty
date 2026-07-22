import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync} from 'node:fs'
import {Codec, CodecDecodeResult} from '@netkitty/codec'
import {IPcapPacketInfo, PcapParserCore} from '@netkitty/pcap-core'
import {Analysis} from '../../src/Analysis'
import {Frame} from '../../src/types/Frame'
import {FrameRow} from '../../src/types/FrameRow'
import {canonicalConversationKey, flowOf, topProtocolOf} from '../../src/indexer/ConversationKey'
import {FixtureCapturePath} from '../lib/Fixtures'

type ExpectedFrame = {packetLength: number, timestamp: number, topProtocol: string, conversationKey: string | null}

//Reference frames via a direct in-memory parse — the oracle the facade must reproduce.
async function directParse(name: string): Promise<ExpectedFrame[]> {
    const codec: Codec = new Codec()
    const frames: {info: IPcapPacketInfo, data: Buffer}[] = []
    let last: Buffer = Buffer.alloc(0)
    const parser: PcapParserCore = new PcapParserCore({
        onPacketData: (data: Buffer): void => {last = Buffer.from(data)},
        onPacket: (info: IPcapPacketInfo): void => {frames.push({info: info, data: last})}
    })
    parser.write(readFileSync(FixtureCapturePath(name)))
    parser.end()
    const out: ExpectedFrame[] = []
    for (const frame of frames) {
        const layers: CodecDecodeResult[] = await codec.decode(frame.data)
        out.push({
            packetLength: frame.info.packetLength,
            timestamp: frame.info.seconds + frame.info.microseconds / 1_000_000,
            topProtocol: topProtocolOf(layers),
            conversationKey: flowOf(layers) ? canonicalConversationKey(flowOf(layers)!) : null
        })
    }
    return out
}

test('analysis: open indexes a pcapng and frameCount/getFrames match a direct parse', async (): Promise<void> => {
    const expected: ExpectedFrame[] = await directParse('tcp-1.pcapng')
    const analysis: Analysis = new Analysis()
    let completed: boolean = false
    analysis.on('complete', (): void => {completed = true})
    await analysis.open(FixtureCapturePath('tcp-1.pcapng'))
    assert.strictEqual(analysis.frameCount(), expected.length)
    assert.strictEqual(completed, true, 'complete event fired')
    const rows: FrameRow[] = await analysis.getFrames(0, expected.length)
    assert.strictEqual(rows.length, expected.length)
    for (let i: number = 0; i < expected.length; i++) {
        assert.strictEqual(rows[i].index, i)
        assert.strictEqual(rows[i].length, expected[i].packetLength, `frame ${i}: length`)
        assert.strictEqual(rows[i].timestamp, expected[i].timestamp, `frame ${i}: timestamp`)
        assert.strictEqual(rows[i].topProtocol, expected[i].topProtocol, `frame ${i}: protocol`)
        assert.strictEqual(rows[i].conversationKey, expected[i].conversationKey, `frame ${i}: conversation`)
    }
    await analysis.close()
})

test('analysis: getFrame returns decoded layers for one frame', async (): Promise<void> => {
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('tcp-1.pcapng'))
    const frame: Frame | null = await analysis.getFrame(0)
    assert.ok(frame, 'frame 0 exists')
    assert.strictEqual(frame!.index, 0)
    assert.ok(Array.isArray(frame!.layers) && frame!.layers.length > 0, 'has decoded layers')
    assert.strictEqual(frame!.layers[0].id, 'eth', 'first layer is ethernet')
    await analysis.close()
})

test('analysis: classic pcap (iec104) indexes and reports its frame count', async (): Promise<void> => {
    const expected: ExpectedFrame[] = await directParse('iec104.pcap')
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('iec104.pcap'))
    assert.strictEqual(analysis.frameCount(), expected.length)
    assert.ok(expected.length > 0)
    await analysis.close()
})

test('analysis: progress events fire and reach the full byte size', async (): Promise<void> => {
    const path: string = FixtureCapturePath('iec104.pcap')
    const analysis: Analysis = new Analysis()
    let lastBytes: number = 0
    let lastTotal: number = 0
    analysis.on('progress', (bytesRead: number, totalBytes: number): void => {lastBytes = bytesRead; lastTotal = totalBytes})
    await analysis.open(path)
    assert.ok(lastTotal > 0, 'progress fired')
    assert.strictEqual(lastTotal, readFileSync(path).length)
    assert.strictEqual(lastBytes, lastTotal)
    await analysis.close()
})

test('analysis: querying before open throws', async (): Promise<void> => {
    const analysis: Analysis = new Analysis()
    await assert.rejects(analysis.getFrames(0, 1), /no open source/)
})
