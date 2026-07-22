import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync, mkdtempSync} from 'node:fs'
import {tmpdir} from 'node:os'
import path from 'node:path'
import {PcapReader} from '../../src/PcapReader'
import {PcapWriter} from '../../src/PcapWriter'
import {FixtureCapturePath} from '../lib/Fixtures'
import {IPcapPacketInfo} from '@netkitty/pcap-core'

async function ReadAll(filename: string): Promise<IPcapPacketInfo[]> {
    return new Promise((resolve, reject): void => {
        const reader: PcapReader = new PcapReader({filename: filename, watch: false})
        const packets: IPcapPacketInfo[] = []
        reader.on('packet', (info: IPcapPacketInfo): number => packets.push(info))
        reader.once('error', reject)
        reader.once('done', (): void => resolve(packets))
        void reader.start()
    })
}

test('PcapWriter format:pcapng writes a file that reads back as pcapng with identical frames', async (): Promise<void> => {
    const source: IPcapPacketInfo[] = await ReadAll(FixtureCapturePath('iec104.pcap'))
    const dir: string = mkdtempSync(path.join(tmpdir(), 'netkitty-ng-'))
    const out: string = path.join(dir, 'out.pcapng')

    const writer: PcapWriter = new PcapWriter({filename: out, format: 'pcapng'})
    for (const info of source) {
        writer.write(Buffer.from(info.packet, 'base64'), info.seconds, info.microseconds)
    }
    await writer.close()

    //file starts with the pcapng Section Header Block magic
    assert.strictEqual(readFileSync(out).toString('hex', 0, 4), '0a0d0d0a')

    const roundReader: PcapReader = new PcapReader({filename: out, watch: false})
    const round: IPcapPacketInfo[] = []
    roundReader.on('packet', (info: IPcapPacketInfo): number => round.push(info))
    await new Promise<void>((resolve, reject): void => {
        roundReader.once('error', reject)
        roundReader.once('done', (): void => resolve())
        void roundReader.start()
    })
    assert.strictEqual(round.length, source.length)
    for (let i: number = 0; i < source.length; i++) {
        assert.strictEqual(round[i].packet, source[i].packet, `frame ${i} bytes`)
        assert.strictEqual(round[i].seconds, source[i].seconds, `frame ${i} seconds`)
        assert.strictEqual(round[i].microseconds, source[i].microseconds, `frame ${i} microseconds`)
    }
    //readPacketData via the round-trip reader's own offsets returns the original frame
    const mid: number = Math.floor(source.length / 2)
    const frame: Buffer = await roundReader.readPacketData(round[mid])
    assert.strictEqual(frame.toString('base64'), source[mid].packet)
    await roundReader.close()
})

test('PcapWriter default format stays classic pcap', async (): Promise<void> => {
    const dir: string = mkdtempSync(path.join(tmpdir(), 'netkitty-cl-'))
    const out: string = path.join(dir, 'out.pcap')
    const writer: PcapWriter = new PcapWriter({filename: out})
    writer.write(Buffer.from('001122334455', 'hex'), 1, 2)
    await writer.close()
    //classic pcap global-header magic (big-endian a1b2c3d4, as GeneratePCAPHeader writes)
    assert.strictEqual(readFileSync(out).toString('hex', 0, 4), 'a1b2c3d4')
})
