import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync, writeFileSync, copyFileSync, mkdtempSync} from 'node:fs'
import {tmpdir} from 'node:os'
import path from 'node:path'
import {PcapReader} from '../../src/PcapReader'
import {PcapEdit, PcapEditHandler} from '../../src/PcapEdit'
import {FixtureCapturePath} from '../lib/Fixtures'
import {IPcapPacketInfo} from '@netkitty/pcap-core'

function tmp(name: string): string {
    return path.join(mkdtempSync(path.join(tmpdir(), 'netkitty-edit-')), name)
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

const IN: string = FixtureCapturePath('iec104.pcap')

test('rewrite: keep-all (undefined) reproduces every frame and timestamp', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const out: string = tmp('keep.pcap')
    const result: {read: number, written: number} = await PcapEdit.rewrite({input: IN, output: out, onPacket: (): void => undefined})
    assert.strictEqual(result.read, src.length)
    assert.strictEqual(result.written, src.length)
    const round: IPcapPacketInfo[] = await readAll(out)
    assert.strictEqual(round.length, src.length)
    for (let i: number = 0; i < src.length; i++) {
        assert.strictEqual(round[i].packet, src[i].packet)
        assert.strictEqual(round[i].seconds, src[i].seconds)
        assert.strictEqual(round[i].microseconds, src[i].microseconds)
    }
})

test('rewrite: filter (return null) drops packets', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const out: string = tmp('filter.pcap')
    const result: {read: number, written: number} = await PcapEdit.rewrite({
        input: IN, output: out,
        onPacket: (_frame: Buffer, info: IPcapPacketInfo): null | void => info.index % 2 === 0 ? null : undefined
    })
    const kept: number = src.filter((_p: IPcapPacketInfo, i: number): boolean => (i + 1) % 2 !== 0).length
    assert.strictEqual(result.written, kept)
    assert.strictEqual((await readAll(out)).length, kept)
})

test('rewrite: replace bytes (Buffer) and expand (array) work', async (): Promise<void> => {
    const out: string = tmp('map.pcap')
    const replacement: Buffer = Buffer.from('deadbeef', 'hex')
    const result: {read: number, written: number} = await PcapEdit.rewrite({
        input: IN, output: out,
        onPacket: (_frame: Buffer, info: IPcapPacketInfo): Buffer | Buffer[] => info.index === 1
            ? [replacement, replacement]   // expand first packet into two
            : replacement                   // replace all others
    })
    const round: IPcapPacketInfo[] = await readAll(out)
    assert.strictEqual(result.written, result.read + 1)   // one packet expanded to two
    assert.strictEqual(round.length, result.written)
    assert.strictEqual(Buffer.from(round[0].packet, 'base64').toString('hex'), 'deadbeef')
})

test('rewrite: converts pcap to pcapng', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const out: string = tmp('converted.pcapng')
    await PcapEdit.rewrite({input: IN, output: out, format: 'pcapng', onPacket: (): void => undefined})
    assert.strictEqual(readFileSync(out).toString('hex', 0, 4), '0a0d0d0a')   // pcapng SHB magic
    const round: IPcapPacketInfo[] = await readAll(out)
    assert.strictEqual(round.length, src.length)
    for (let i: number = 0; i < src.length; i++) assert.strictEqual(round[i].packet, src[i].packet)
})

test('rewrite: reads a compressed input transparently', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const out: string = tmp('from-lz4.pcap')
    await PcapEdit.rewrite({input: FixtureCapturePath('iec104.pcap.lz4'), output: out, onPacket: (): void => undefined})
    assert.strictEqual((await readAll(out)).length, src.length)
})

test('rewrite: refuses input === output', async (): Promise<void> => {
    await assert.rejects((): Promise<unknown> => PcapEdit.rewrite({input: IN, output: IN, onPacket: (): void => undefined}), /different files/)
})

test('transform: shiftTime moves every timestamp by a fixed offset', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const out: string = tmp('shift.pcap')
    await PcapEdit.rewrite({input: IN, output: out, onPacket: PcapEdit.chain(PcapEdit.shiftTime(100, 0))})
    const round: IPcapPacketInfo[] = await readAll(out)
    for (let i: number = 0; i < src.length; i++) assert.strictEqual(round[i].seconds, src[i].seconds + 100)
})

test('transform: constantInterval spaces packets evenly from the first timestamp', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const out: string = tmp('interval.pcap')
    await PcapEdit.rewrite({input: IN, output: out, onPacket: PcapEdit.chain(PcapEdit.constantInterval(1000))})
    const round: IPcapPacketInfo[] = await readAll(out)
    const start: number = src[0].seconds * 1000000 + src[0].microseconds
    for (let i: number = 0; i < round.length; i++) {
        assert.strictEqual(round[i].seconds * 1000000 + round[i].microseconds, start + i * 1000)
    }
})

test('transform: setStartTime rebases while preserving gaps; scaleTime stretches them', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const gap0: number = (src[1].seconds - src[0].seconds) * 1000000 + (src[1].microseconds - src[0].microseconds)

    const rebased: string = tmp('start.pcap')
    await PcapEdit.rewrite({input: IN, output: rebased, onPacket: PcapEdit.chain(PcapEdit.setStartTime(0, 0))})
    const r: IPcapPacketInfo[] = await readAll(rebased)
    assert.strictEqual(r[0].seconds, 0)
    assert.strictEqual(r[0].microseconds, 0)
    assert.strictEqual(r[1].seconds * 1000000 + r[1].microseconds, gap0)   // gap preserved

    const scaled: string = tmp('scale.pcap')
    await PcapEdit.rewrite({input: IN, output: scaled, onPacket: PcapEdit.chain(PcapEdit.setStartTime(0, 0), PcapEdit.scaleTime(2))})
    const s: IPcapPacketInfo[] = await readAll(scaled)
    assert.strictEqual(s[1].seconds * 1000000 + s[1].microseconds, gap0 * 2)   // gap doubled
})

test('transform: MAC set/swap edit the Ethernet header bytes', async (): Promise<void> => {
    const out: string = tmp('mac.pcap')
    await PcapEdit.rewrite({
        input: IN, output: out,
        onPacket: PcapEdit.chain(PcapEdit.setDestinationMac('01:02:03:04:05:06'), PcapEdit.setSourceMac('aa:bb:cc:dd:ee:ff'))
    })
    const reader: PcapReader = new PcapReader({filename: out, watch: false})
    const infos: IPcapPacketInfo[] = []
    reader.on('packet', (info: IPcapPacketInfo): number => infos.push(info))
    await new Promise<void>((resolve, reject): void => { reader.once('error', reject); reader.once('done', (): void => resolve()); void reader.start() })
    const frame0: Buffer = await reader.readPacketData(infos[0])
    await reader.close()
    assert.strictEqual(frame0.toString('hex', 0, 6), '010203040506')    // destination MAC
    assert.strictEqual(frame0.toString('hex', 6, 12), 'aabbccddeeff')   // source MAC
})

test('transform: swapMac exchanges src and dst; invalid MAC throws', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const origFrame0: Buffer = Buffer.from(src[0].packet, 'base64')
    const out: string = tmp('swap.pcap')
    await PcapEdit.rewrite({input: IN, output: out, onPacket: PcapEdit.chain(PcapEdit.swapMac())})
    const round: IPcapPacketInfo[] = await readAll(out)
    const swapped: Buffer = Buffer.from(round[0].packet, 'base64')
    assert.strictEqual(swapped.toString('hex', 0, 6), origFrame0.toString('hex', 6, 12))
    assert.strictEqual(swapped.toString('hex', 6, 12), origFrame0.toString('hex', 0, 6))
    assert.throws((): unknown => PcapEdit.setSourceMac('nope'), /invalid MAC/)
})

test('rewrite: a handler that throws on every packet rejects cleanly (no process crash)', async (): Promise<void> => {
    const out: string = tmp('throwing.pcap')
    //the input has many packets, so the handler throws more than once — this must reject, not crash the
    //process on a second emit('error') to a consumed one-shot listener
    await assert.rejects(
        (): Promise<unknown> => PcapEdit.rewrite({input: IN, output: out, onPacket: (): never => { throw new Error('boom') }}),
        /boom/
    )
})

test('rewrite: a handler returning a null frame does not throw (falls back to the original bytes)', async (): Promise<void> => {
    const src: IPcapPacketInfo[] = await readAll(IN)
    const out: string = tmp('nullframe.pcap')
    //deliberately violate the type (frame: null) to prove the runtime guard prevents a writer crash
    const badHandler: PcapEditHandler = ((_frame: Buffer, info: IPcapPacketInfo): unknown => ({frame: null, seconds: info.seconds})) as PcapEditHandler
    const result: {read: number, written: number} = await PcapEdit.rewrite({input: IN, output: out, onPacket: badHandler})
    assert.strictEqual(result.written, src.length)
    const round: IPcapPacketInfo[] = await readAll(out)
    assert.strictEqual(round[0].packet, src[0].packet)   // original frame preserved
})

test('patchInPlace: same-length overwrite works; wrong length and compressed files are rejected', async (): Promise<void> => {
    const work: string = tmp('patch.pcap')
    copyFileSync(IN, work)
    const infos: IPcapPacketInfo[] = await readAll(work)
    const target: IPcapPacketInfo = infos[3]
    const replacement: Buffer = Buffer.alloc(target.packetLength, 0x5a)
    await PcapEdit.patchInPlace(work, target, replacement)
    // re-read: the patched packet is now all 0x5a, others unchanged
    const after: IPcapPacketInfo[] = await readAll(work)
    assert.strictEqual(Buffer.from(after[3].packet, 'base64').toString('hex'), replacement.toString('hex'))
    assert.strictEqual(after[0].packet, infos[0].packet)
    // wrong length rejected
    await assert.rejects((): Promise<void> => PcapEdit.patchInPlace(work, target, Buffer.alloc(target.packetLength + 1)), /same length/)
    // compressed file rejected
    const gz: string = tmp('c.pcap.gz')
    writeFileSync(gz, readFileSync(FixtureCapturePath('iec104.pcap.gz')))
    await assert.rejects((): Promise<void> => PcapEdit.patchInPlace(gz, target, Buffer.alloc(target.packetLength)), /compressed/)
})
