import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync, writeFileSync, appendFileSync, rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import path from 'node:path'
import {IPcapPacketInfo, PcapParserCore} from '@netkitty/pcap-core'
import {Analysis} from '../../src/lib/streaming/Analysis'
import {FrameRow} from '../../src/lib/streaming/types/FrameRow'
import {ConversationsReducer, ConversationSummary} from '../../src/lib/streaming/reducers/ConversationsReducer'
import {FixtureCapturePath} from '../lib/Fixtures'

function totalFrames(buffer: Buffer): number {
    let count: number = 0
    const parser: PcapParserCore = new PcapParserCore({onPacket: (_info: IPcapPacketInfo): void => {count++}})
    parser.write(buffer)
    parser.end()
    return count
}

async function waitFor(predicate: () => boolean, timeoutMs: number = 20000): Promise<void> {
    const started: number = Date.now()
    while (!predicate()) {
        if (Date.now() - started > timeoutMs) throw new Error('waitFor timed out')
        await new Promise<void>((resolve: () => void): void => {setTimeout(resolve, 50)})
    }
}

function tempCopy(name: string): {path: string, golden: Buffer} {
    const golden: Buffer = readFileSync(FixtureCapturePath(name))
    const target: string = path.join(tmpdir(), `netkitty-watch-${process.pid}-${name.replace(/[^a-z0-9]/gi, '_')}`)
    return {path: target, golden: golden}
}

test('watch: tailing a growing capture indexes newly appended frames', async (): Promise<void> => {
    const {path: temp, golden}: {path: string, golden: Buffer} = tempCopy('iec104.pcap')
    const total: number = totalFrames(golden)
    const half: number = Math.floor(golden.length / 2)
    writeFileSync(temp, golden.subarray(0, half))
    const analysis: Analysis = new Analysis()
    const rows: FrameRow[] = []
    analysis.on('frame', (row: FrameRow): void => {rows.push(row)})
    try {
        await analysis.watch(temp)
        const afterHalf: number = analysis.frameCount()
        assert.ok(afterHalf > 0 && afterHalf < total, `partial index ${afterHalf} of ${total}`)
        appendFileSync(temp, golden.subarray(half))
        await waitFor((): boolean => analysis.frameCount() === total)
        assert.strictEqual(analysis.frameCount(), total)
        assert.strictEqual(rows.length, total, 'a frame event per indexed frame')
        assert.strictEqual(rows[rows.length - 1].index, total - 1)
    } finally {
        await analysis.close()
        rmSync(temp, {force: true})
    }
})

test('watch: attached reducer receives live frames', async (): Promise<void> => {
    const {path: temp, golden}: {path: string, golden: Buffer} = tempCopy('iec104.pcap')
    const total: number = totalFrames(golden)
    const half: number = Math.floor(golden.length / 2)
    writeFileSync(temp, golden.subarray(0, half))
    const analysis: Analysis = new Analysis()
    const conversations: ConversationsReducer = new ConversationsReducer()
    try {
        await analysis.watch(temp)
        await analysis.attachReducer(conversations)
        const packetsAfterHalf: number = conversations.result().reduce((sum: number, c: ConversationSummary): number => sum + c.packets, 0)
        appendFileSync(temp, golden.subarray(half))
        await waitFor((): boolean => analysis.frameCount() === total)
        //Give the last live frames a tick to feed the reducer.
        await waitFor((): boolean => conversations.result().reduce((sum: number, c: ConversationSummary): number => sum + c.packets, 0) >= total, 4000)
        const packetsFinal: number = conversations.result().reduce((sum: number, c: ConversationSummary): number => sum + c.packets, 0)
        assert.strictEqual(packetsFinal, total, 'reducer saw replay + live frames')
        assert.ok(packetsFinal > packetsAfterHalf, 'live frames grew the reducer')
    } finally {
        await analysis.close()
        rmSync(temp, {force: true})
    }
})

test('watch: maxFrames caps the index via FIFO eviction', async (): Promise<void> => {
    const {path: temp, golden}: {path: string, golden: Buffer} = tempCopy('iec104.pcap')
    const total: number = totalFrames(golden)
    const cap: number = Math.max(2, Math.floor(total / 3))
    writeFileSync(temp, golden)
    const analysis: Analysis = new Analysis({maxFrames: cap})
    try {
        await analysis.watch(temp)
        await waitFor((): boolean => analysis.frameCount() >= total)
        const frames: FrameRow[] = await analysis.getFrames(0, total)
        assert.ok(frames.length <= cap, `retained ${frames.length} <= cap ${cap}`)
        //The oldest frames were evicted; the newest survive.
        assert.strictEqual(frames[frames.length - 1].index, total - 1)
    } finally {
        await analysis.close()
        rmSync(temp, {force: true})
    }
})
