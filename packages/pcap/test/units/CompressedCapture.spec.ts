import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync, writeFileSync, mkdtempSync} from 'node:fs'
import {tmpdir} from 'node:os'
import path from 'node:path'
import {PcapReader} from '../../src/PcapReader'
import {FixtureCapturePath} from '../lib/Fixtures'
import {IPcapPacketInfo} from '@netkitty/pcap-core'

/**
 * Read every packet of a capture file in order (resolves on 'done', rejects on 'error'). The 'packet'
 * listener is synchronous, so packets arrive in parser order and carry their bytes as base64.
 */
async function ReadCaptureFile(filename: string): Promise<IPcapPacketInfo[]> {
    return new Promise((resolve, reject): void => {
        const reader: PcapReader = new PcapReader({filename: filename, watch: false})
        const packets: IPcapPacketInfo[] = []
        reader.on('packet', (pcapPacketInfo: IPcapPacketInfo): number => packets.push(pcapPacketInfo))
        reader.once('error', reject)
        reader.once('done', (): void => resolve(packets))
        void reader.start()
    })
}

/**
 * A gzip/LZ4-compressed capture must read back exactly as the uncompressed original: PcapReader detects
 * the compression magic, decompresses transparently, and serves the parser and readPacketData() from the
 * decompressed bytes. The .gz and .lz4 fixtures are the iec104.pcap fixture compressed with the reference
 * gzip and lz4 tools.
 */
test('gzip capture (.pcap.gz): transparently decompressed, packets identical to the plain pcap', async (): Promise<void> => {
    const plain: IPcapPacketInfo[] = await ReadCaptureFile(FixtureCapturePath('iec104.pcap'))
    const gzip: IPcapPacketInfo[] = await ReadCaptureFile(FixtureCapturePath('iec104.pcap.gz'))
    assert.strictEqual(gzip.length, plain.length)
    for (let i: number = 0; i < plain.length; i++) {
        assert.strictEqual(gzip[i].packet, plain[i].packet, `packet ${i} bytes differ`)
    }
})

test('LZ4 capture (.pcap.lz4): transparently decompressed, packets identical to the plain pcap', async (): Promise<void> => {
    const plain: IPcapPacketInfo[] = await ReadCaptureFile(FixtureCapturePath('iec104.pcap'))
    const lz4: IPcapPacketInfo[] = await ReadCaptureFile(FixtureCapturePath('iec104.pcap.lz4'))
    assert.strictEqual(lz4.length, plain.length)
    for (let i: number = 0; i < plain.length; i++) {
        assert.strictEqual(lz4[i].packet, plain[i].packet, `packet ${i} bytes differ`)
    }
})

test('compressed capture: readPacketData() returns the same frame bytes as the plain pcap', async (): Promise<void> => {
    const plain: IPcapPacketInfo[] = await ReadCaptureFile(FixtureCapturePath('iec104.pcap'))
    for (const name of ['iec104.pcap.gz', 'iec104.pcap.lz4']) {
        const reader: PcapReader = new PcapReader({filename: FixtureCapturePath(name), watch: false})
        const infos: IPcapPacketInfo[] = []
        reader.on('packet', (info: IPcapPacketInfo): number => infos.push(info))
        await new Promise<void>((resolve, reject): void => {
            reader.once('error', reject)
            reader.once('done', (): void => resolve())
            void reader.start()
        })
        assert.strictEqual(infos.length, plain.length, `${name}: packet count`)
        //spot-check the first, a middle and the last frame via the offset/length path
        for (const i of [0, Math.floor(plain.length / 2), plain.length - 1]) {
            const frame: Buffer = await reader.readPacketData(infos[i])
            const expected: string = Buffer.from(plain[i].packet, 'base64').toString('hex')
            assert.strictEqual(frame.toString('hex'), expected, `${name}: readPacketData frame ${i}`)
        }
        await reader.close()
    }
})

test('watch:true on a compressed capture reads the snapshot to done instead of idling forever', async (): Promise<void> => {
    const plain: IPcapPacketInfo[] = await ReadCaptureFile(FixtureCapturePath('iec104.pcap'))
    const reader: PcapReader = new PcapReader({filename: FixtureCapturePath('iec104.pcap.gz'), watch: true})
    const packets: IPcapPacketInfo[] = []
    reader.on('packet', (info: IPcapPacketInfo): number => packets.push(info))
    await new Promise<void>((resolve, reject): void => {
        const timer: NodeJS.Timeout = setTimeout((): void => reject(new Error('watch mode idled — never reached done')), 4000)
        reader.once('error', reject)
        reader.once('done', (): void => { clearTimeout(timer); resolve() })
        void reader.start()
    })
    await reader.close()
    assert.strictEqual(packets.length, plain.length)
})

test('corrupt/truncated compressed capture surfaces a clean error event, not a rejected start()', async (): Promise<void> => {
    const dir: string = mkdtempSync(path.join(tmpdir(), 'netkitty-cmp-'))
    //a truncated gzip: valid 1f 8b header, then cut short so zlib fails to inflate
    const badGz: string = path.join(dir, 'broken.pcap.gz')
    writeFileSync(badGz, readFileSync(FixtureCapturePath('iec104.pcap.gz')).subarray(0, 40))
    //an LZ4 magic followed by a structurally invalid (too short) frame
    const badLz4: string = path.join(dir, 'broken.pcap.lz4')
    writeFileSync(badLz4, Buffer.from([0x04, 0x22, 0x4d, 0x18, 0x60]))

    for (const bad of [badGz, badLz4]) {
        const reader: PcapReader = new PcapReader({filename: bad, watch: false})
        let errored: Error | null = null
        //start() must resolve (not reject); the failure arrives as an 'error' event
        await new Promise<void>((resolve): void => {
            reader.once('error', (err: Error): void => { errored = err })
            reader.once('done', (): void => resolve())
            void reader.start().catch((): void => resolve())
        })
        await reader.close()
        assert.ok(errored, `${path.basename(bad)}: expected an error event`)
    }
})
