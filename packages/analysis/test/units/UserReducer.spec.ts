import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync} from 'node:fs'
import {IPcapPacketInfo, PcapParserCore} from '@netkitty/pcap-core'
import {Analysis} from '../../src/lib/streaming/Analysis'
import {Frame} from '../../src/lib/streaming/types/Frame'
import {UpdateContext} from '../../src/lib/streaming/types/UpdateContext'
import {IAnalysisReducer} from '../../src/lib/streaming/interfaces/IAnalysisReducer'
import {reduceReducer, groupByReducer} from '../../src/lib/streaming/reducers/ReducerFactories'
import {FixtureCapturePath} from '../lib/Fixtures'

function frameCountAndBytes(name: string): {count: number, bytes: number} {
    let count: number = 0
    let bytes: number = 0
    const parser: PcapParserCore = new PcapParserCore({
        onPacket: (info: IPcapPacketInfo): void => {count++; bytes += info.packetLength}
    })
    parser.write(readFileSync(FixtureCapturePath(name)))
    parser.end()
    return {count: count, bytes: bytes}
}

test('user reducer: reduceReducer sums bytes over the replayed stream', async (): Promise<void> => {
    const expected: {count: number, bytes: number} = frameCountAndBytes('tcp-1.pcapng')
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('tcp-1.pcapng'))
    const totalBytes: IAnalysisReducer<number> = reduceReducer<number>(0, (accumulator: number, frame: Frame): number => accumulator + frame.length)
    await analysis.attachReducer(totalBytes)
    assert.strictEqual(totalBytes.result(), expected.bytes)
    await analysis.close()
})

test('user reducer: groupByReducer counts frames per top protocol', async (): Promise<void> => {
    const expected: {count: number} = frameCountAndBytes('tcp-1.pcapng')
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('tcp-1.pcapng'))
    const perProtocol: IAnalysisReducer<Map<string, number>> = groupByReducer<string, number>(
        (frame: Frame): string => frame.topProtocol,
        0,
        (count: number): number => count + 1
    )
    await analysis.attachReducer(perProtocol)
    const groups: Map<string, number> = perProtocol.result()
    let total: number = 0
    for (const value of groups.values()) total += value
    assert.strictEqual(total, expected.count, 'group counts sum to frame count')
    await analysis.close()
})

test('user reducer: needs projection delivers only the declared layers', async (): Promise<void> => {
    const seenLayerIds: Set<string> = new Set<string>()
    const ethOnly: IAnalysisReducer<number> = {
        needs: ['eth'],
        update(frame: Frame): void {
            for (const layer of frame.layers) seenLayerIds.add(layer.id)
        },
        result(): number {return seenLayerIds.size},
        reset(): void {seenLayerIds.clear()}
    }
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('tcp-1.pcapng'))
    await analysis.attachReducer(ethOnly)
    assert.deepStrictEqual([...seenLayerIds], ['eth'], 'only the eth layer is delivered')
    await analysis.close()
})

test('user reducer: replay feeds UpdateContext with phase=replay and a running index', async (): Promise<void> => {
    const indices: number[] = []
    let phase: string = ''
    let total: number = -1
    const probe: IAnalysisReducer<number> = {
        update(frame: Frame, context: UpdateContext): void {
            indices.push(context.index)
            phase = context.phase
            total = context.total
        },
        result(): number {return indices.length},
        reset(): void {indices.length = 0}
    }
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('tcp-1.pcapng'))
    await analysis.attachReducer(probe)
    assert.strictEqual(phase, 'replay')
    assert.strictEqual(total, analysis.frameCount())
    assert.deepStrictEqual(indices, indices.slice().sort((a: number, b: number): number => a - b), 'indices are monotonic')
    assert.strictEqual(indices[0], 0)
    await analysis.close()
})
