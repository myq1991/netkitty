import {test} from 'node:test'
import assert from 'node:assert'
import {mkdtempSync} from 'node:fs'
import {tmpdir} from 'node:os'
import path from 'node:path'
import {PcapReader} from '../../src/PcapReader'
import {PcapEdit, IPcapProgress, RetimeEdit} from '../../src/PcapEdit'
import {FixtureCapturePath} from '../lib/Fixtures'
import {IPcapPacketInfo} from '@netkitty/pcap-core'

const IN: string = FixtureCapturePath('iec104.pcap')

function tmp(name: string): string {
    return path.join(mkdtempSync(path.join(tmpdir(), 'netkitty-retime-')), name)
}

/** absolute microseconds of a packet */
function micros(info: IPcapPacketInfo): number {
    return info.seconds * 1000000 + info.microseconds
}

async function readAll(filename: string): Promise<IPcapPacketInfo[]> {
    return new Promise((resolve, reject): void => {
        const reader: PcapReader = new PcapReader({filename: filename, watch: false})
        const packets: IPcapPacketInfo[] = []
        reader.on('packet', (info: IPcapPacketInfo): number => packets.push(info))
        reader.once('error', reject)
        reader.once('done', (): void => resolve(packets))
        void reader.start()
    })
}

async function retimeAndRead(edit: RetimeEdit, range?: {from: number, to?: number}): Promise<IPcapPacketInfo[]> {
    const out: string = tmp('out.pcap')
    await PcapEdit.retime({input: IN, output: out, edit: edit, range: range})
    return readAll(out)
}

test('retime constantInterval, whole file: spaces packets evenly from the first timestamp', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const round: IPcapPacketInfo[] = await retimeAndRead({type: 'constantInterval', interval: 1, unit: 'ms'})
    const start: number = micros(src[0])
    for (let i: number = 0; i < round.length; i++) assert.strictEqual(micros(round[i]), start + i * 1000)
})

test('retime constantInterval with a frame window: before untouched, after shifted to preserve continuity', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const from: number = 10
    const to: number = 20
    const round: IPcapPacketInfo[] = await retimeAndRead({type: 'constantInterval', interval: 1000}, {from: from, to: to})
    assert.strictEqual(round.length, src.length)

    const anchor: number = micros(src[from - 1]) //frame `from` (1-based) keeps its time
    //before the range: byte-for-timestamp identical
    for (let i: number = 0; i < from - 1; i++) assert.strictEqual(micros(round[i]), micros(src[i]))
    //in range: anchor + k*interval
    for (let k: number = 0; k <= to - from; k++) assert.strictEqual(micros(round[from - 1 + k]), anchor + k * 1000)
    //boundary gap out of the range is preserved
    const origBoundaryGap: number = micros(src[to]) - micros(src[to - 1])
    assert.strictEqual(micros(round[to]) - micros(round[to - 1]), origBoundaryGap)
    //after the range: rigid translation by a single constant shift, and all original gaps preserved
    const shift: number = micros(round[to - 1]) - micros(src[to - 1])
    for (let i: number = to; i < src.length; i++) assert.strictEqual(micros(round[i]) - micros(src[i]), shift)
})

test('retime scale with a window: in-range gaps scale, after-range gaps preserved exactly', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const from: number = 5
    const to: number = 15
    const round: IPcapPacketInfo[] = await retimeAndRead({type: 'scale', factor: 2}, {from: from, to: to})
    const anchor: number = micros(src[from - 1])
    assert.strictEqual(micros(round[from - 1]), anchor) //anchor unchanged
    //each in-range gap doubled relative to the anchor
    for (let i: number = from; i <= to; i++) {
        assert.strictEqual(micros(round[i - 1]), Math.round(anchor + (micros(src[i - 1]) - anchor) * 2))
    }
    //after-range inter-frame gaps identical to the original (rigid translation)
    for (let i: number = to; i < src.length - 1; i++) {
        assert.strictEqual(micros(round[i + 1]) - micros(round[i]), micros(src[i + 1]) - micros(src[i]))
    }
})

test('retime: monotonic input stays monotonic after an expanded (scale>1) window', async (): Promise<void> => {
    const round: IPcapPacketInfo[] = await retimeAndRead({type: 'scale', factor: 3}, {from: 20, to: 40})
    for (let i: number = 1; i < round.length; i++) assert.ok(micros(round[i]) >= micros(round[i - 1]), `frame ${i} went backwards`)
})

test('retime: window at file end retimes the tail and shifts nobody', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const round: IPcapPacketInfo[] = await retimeAndRead({type: 'constantInterval', interval: 500}, {from: src.length - 2})
    for (let i: number = 0; i < src.length - 3; i++) assert.strictEqual(micros(round[i]), micros(src[i]))   //untouched head
})

test('retime: single-frame window is a no-op for interval edits', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const round: IPcapPacketInfo[] = await retimeAndRead({type: 'constantInterval', interval: 999999}, {from: 7, to: 7})
    for (let i: number = 0; i < src.length; i++) assert.strictEqual(micros(round[i]), micros(src[i]))
})

test('retime: a window past EOF leaves the whole file untouched', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const round: IPcapPacketInfo[] = await retimeAndRead({type: 'scale', factor: 5}, {from: 10000, to: 20000})
    for (let i: number = 0; i < src.length; i++) assert.strictEqual(micros(round[i]), micros(src[i]))
})

test('retime: invalid options are rejected at call time', async (): Promise<void> => {
    const out: string = tmp('x.pcap')
    await assert.rejects((): Promise<unknown> => PcapEdit.retime({input: IN, output: out, edit: {type: 'scale', factor: 1}, range: {from: 20, to: 10}}), /range\.to/)
    await assert.rejects((): Promise<unknown> => PcapEdit.retime({input: IN, output: out, edit: {type: 'scale', factor: -1}}), /factor/)
    await assert.rejects((): Promise<unknown> => PcapEdit.retime({input: IN, output: out, edit: {type: 'scale', factor: Infinity}}), /factor/)
    await assert.rejects((): Promise<unknown> => PcapEdit.retime({input: IN, output: out, edit: {type: 'setStart', seconds: 0}, range: {from: 5, to: 10}}), /setStart/)
    await assert.rejects((): Promise<unknown> => PcapEdit.retime({input: IN, output: out, edit: {type: 'constantInterval', interval: 1, unit: 'bogus' as never}}), /unknown time unit/)
})

test('retime shift with a from: shifts the suffix, head untouched', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const round: IPcapPacketInfo[] = await retimeAndRead({type: 'shift', delta: 5, unit: 's'}, {from: 50})
    for (let i: number = 0; i < 49; i++) assert.strictEqual(micros(round[i]), micros(src[i]))
    for (let i: number = 49; i < src.length; i++) assert.strictEqual(micros(round[i]), micros(src[i]) + 5000000)
})

test('units: PcapEdit.micros converts, and constantInterval honours a unit', async (): Promise<void> => {
    assert.strictEqual(PcapEdit.micros(1, 'ms'), 1000)
    assert.strictEqual(PcapEdit.micros(2, 's'), 2000000)
    assert.strictEqual(PcapEdit.micros(1, 'min'), 60000000)
    const src: IPcapPacketInfo[] = await readAll(IN)
    const out: string = tmp('u.pcap')
    await PcapEdit.rewrite({input: IN, output: out, onPacket: PcapEdit.chain(PcapEdit.constantInterval(2, 'ms'))})
    const round: IPcapPacketInfo[] = await readAll(out)
    const start: number = micros(src[0])
    for (let i: number = 0; i < round.length; i++) assert.strictEqual(micros(round[i]), start + i * 2000)
})

test('progress: byte-ratio is monotonic, throttled, and ends at exactly 1', async (): Promise<void> => {
    const events: IPcapProgress[] = []
    const out: string = tmp('p.pcap')
    await PcapEdit.retime({input: IN, output: out, edit: {type: 'shift', delta: 0}, onProgress: (p: IPcapProgress): number => events.push(p)})
    assert.ok(events.length > 0)
    assert.ok(events.length <= 101, `too many progress events: ${events.length}`)
    for (let i: number = 1; i < events.length; i++) assert.ok(events[i].ratio >= events[i - 1].ratio, 'ratio went backwards')
    assert.strictEqual(events[events.length - 1].ratio, 1)
    assert.strictEqual(events[events.length - 1].bytesProcessed, events[events.length - 1].totalBytes)
})

test('progress: a compressed input still reaches ratio 1 (totalBytes = decompressed length)', async (): Promise<void> => {
    const events: IPcapProgress[] = []
    const out: string = tmp('pc.pcap')
    await PcapEdit.rewrite({input: FixtureCapturePath('iec104.pcap.lz4'), output: out, onPacket: (): void => undefined, onProgress: (p: IPcapProgress): number => events.push(p)})
    assert.strictEqual(events[events.length - 1].ratio, 1)
    assert.ok(events[events.length - 1].totalBytes > 0)
})

test('progress: a throwing progress handler does not abort the operation', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const out: string = tmp('pt.pcap')
    const result: {read: number, written: number} = await PcapEdit.rewrite({
        input: IN, output: out,
        onPacket: (): void => undefined,
        onProgress: (): never => { throw new Error('progress boom') }
    })
    assert.strictEqual(result.written, src.length)
})
