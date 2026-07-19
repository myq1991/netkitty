import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync} from 'node:fs'
import {Codec, CodecDecodeResult} from '@netkitty/codec'
import {IPcapPacketInfo, PcapParserCore} from '@netkitty/pcap-core'
import {Analysis} from '../../src/lib/streaming/Analysis'
import {matchesFilter, parseFilter} from '../../src/lib/streaming/filter/FilterExpression'
import {FixtureCapturePath} from '../lib/Fixtures'

//Decode every frame of a fixture, so the test can compute the expected match set independently.
async function decodeAll(name: string): Promise<CodecDecodeResult[][]> {
    const codec: Codec = new Codec()
    const raw: Buffer[] = []
    let last: Buffer = Buffer.alloc(0)
    const parser: PcapParserCore = new PcapParserCore({
        onPacketData: (data: Buffer): void => {last = Buffer.from(data)},
        onPacket: (_info: IPcapPacketInfo): void => {raw.push(last)}
    })
    parser.write(readFileSync(FixtureCapturePath(name)))
    parser.end()
    const out: CodecDecodeResult[][] = []
    for (const data of raw) out.push(await codec.decode(data))
    return out
}

function expectedMatches(frames: CodecDecodeResult[][], displayFilter: string): number[] {
    const expression: ReturnType<typeof parseFilter> = parseFilter(displayFilter)
    const matches: number[] = []
    frames.forEach((layers: CodecDecodeResult[], index: number): void => {
        if (matchesFilter(layers, expression)) matches.push(index)
    })
    return matches
}

test('filter: protocol name selects every frame carrying that layer', async (): Promise<void> => {
    const frames: CodecDecodeResult[][] = await decodeAll('iec104.pcap')
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('iec104.pcap'))
    const got: number[] = await analysis.filter('tcp')
    assert.deepStrictEqual(got, expectedMatches(frames, 'tcp'))
    assert.ok(got.length > 0, 'iec104 frames are TCP')
    assert.deepStrictEqual(await analysis.filter('arp'), [], 'no ARP frames')
    await analysis.close()
})

test('filter: ip.addr matches frames with that source or destination address', async (): Promise<void> => {
    const frames: CodecDecodeResult[][] = await decodeAll('iec104.pcap')
    const ip: CodecDecodeResult | undefined = frames[0].find((l: CodecDecodeResult): boolean => l.id === 'ipv4' || l.id === 'ipv6')
    assert.ok(ip, 'first frame has IP')
    const address: string = String((ip!.data as any).sip)
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('iec104.pcap'))
    const got: number[] = await analysis.filter(`ip.addr == ${address}`)
    assert.deepStrictEqual(got, expectedMatches(frames, `ip.addr == ${address}`))
    assert.ok(got.includes(0), 'frame 0 matches its own address')
    await analysis.close()
})

test('filter: AND combines predicates', async (): Promise<void> => {
    const frames: CodecDecodeResult[][] = await decodeAll('iec104.pcap')
    const tcp: CodecDecodeResult | undefined = frames[0].find((l: CodecDecodeResult): boolean => l.id === 'tcp')
    assert.ok(tcp, 'first frame has TCP')
    const port: string = String((tcp!.data as any).dstport)
    const expression: string = `tcp && tcp.port == ${port}`
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('iec104.pcap'))
    const got: number[] = await analysis.filter(expression)
    assert.deepStrictEqual(got, expectedMatches(frames, expression))
    assert.ok(got.length > 0)
    await analysis.close()
})

test('filter: direction-sensitive ip.src is column-decided via the direction bit, matching a direct eval', async (): Promise<void> => {
    const frames: CodecDecodeResult[][] = await decodeAll('iec104.pcap')
    const ip: CodecDecodeResult | undefined = frames[0].find((l: CodecDecodeResult): boolean => l.id === 'ipv4' || l.id === 'ipv6')
    assert.ok(ip, 'first frame has IP')
    const src: string = String((ip!.data as any).sip)
    const filter: string = `ip.src == ${src}`
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('iec104.pcap'))
    const got: number[] = await analysis.filter(filter)
    //ip.src is direction-sensitive; the index direction bit recovers src/dst from the canonical key,
    //so it is decided from columns (no re-decode) and must still equal the direct evaluation.
    assert.deepStrictEqual(got, expectedMatches(frames, filter))
    assert.ok(got.includes(0), 'frame 0 is from its own source')
    assert.ok(got.length < frames.length, 'only one direction matches — proving direction is honored')
    await analysis.close()
})

test('filter: an unmatched value returns empty', async (): Promise<void> => {
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('iec104.pcap'))
    assert.deepStrictEqual(await analysis.filter('ip.addr == 203.0.113.255'), [])
    await analysis.close()
})

test('filter: empty filter matches every frame', async (): Promise<void> => {
    const analysis: Analysis = new Analysis()
    await analysis.open(FixtureCapturePath('iec104.pcap'))
    const all: number[] = await analysis.filter('')
    assert.strictEqual(all.length, analysis.frameCount())
    await analysis.close()
})
