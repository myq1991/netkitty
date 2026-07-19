import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync} from 'node:fs'
import {LoadPacket, FixtureCapturePath} from '../lib/Fixtures'
import {IPcapPacketInfo, PcapParserCore} from '../../src'

type ParseOutcome = {
    packets: IPcapPacketInfo[]
    error: Error | null
    ended: boolean
}

/**
 * Feed one or more byte chunks into a fresh PcapParserCore and collect the callbacks.
 * The pure core has no streams: the whole capture is written as buffer(s), proving
 * it produces the same result as the streaming shell without any node IO.
 */
function ParseChunks(chunks: Buffer[]): ParseOutcome {
    const outcome: ParseOutcome = {packets: [], error: null, ended: false}
    const core: PcapParserCore = new PcapParserCore({
        onPacket: (info: IPcapPacketInfo): number => outcome.packets.push(info),
        onError: (err: Error): Error => outcome.error = err,
        onEnd: (): boolean => outcome.ended = true
    })
    for (const chunk of chunks) core.write(chunk)
    core.end()
    return outcome
}

/**
 * Parse a whole capture file as a single in-memory buffer
 */
function ParseFile(name: string): ParseOutcome {
    return ParseChunks([readFileSync(FixtureCapturePath(name))])
}

test('core: classic pcap parses all packets, first packet bytes match fixture, format detected', (): void => {
    const outcome: ParseOutcome = ParseFile('GOOSE.pcap')
    assert.strictEqual(outcome.error, null)
    assert.strictEqual(outcome.packets.length, 8)
    const firstPacketHex: string = Buffer.from(outcome.packets[0].packet, 'base64').toString('hex')
    assert.strictEqual(firstPacketHex, LoadPacket('goose/baseline').hex)
    assert.ok(outcome.packets[0].seconds > 0)
    assert.ok(outcome.ended)
})

test('core: format getter reports pcap / pcapng', (): void => {
    const pcap: PcapParserCore = new PcapParserCore()
    pcap.write(readFileSync(FixtureCapturePath('GOOSE.pcap')))
    assert.strictEqual(pcap.format, 'pcap')
    const pcapng: PcapParserCore = new PcapParserCore()
    pcapng.write(readFileSync(FixtureCapturePath('tcp-1.pcapng')))
    assert.strictEqual(pcapng.format, 'pcapng')
})

test('core: larger session file (105-packet IEC104 capture)', (): void => {
    const outcome: ParseOutcome = ParseFile('iec104.pcap')
    assert.strictEqual(outcome.packets.length, 105)
})

test('core: pcapng packet bytes match fixture and 64-bit timestamp resolves', (): void => {
    const outcome: ParseOutcome = ParseFile('tcp-1.pcapng')
    assert.strictEqual(outcome.packets.length, 1)
    const packetHex: string = Buffer.from(outcome.packets[0].packet, 'base64').toString('hex')
    assert.strictEqual(packetHex, LoadPacket('tcp/baseline').hex)
    assert.ok(outcome.packets[0].seconds > 1_500_000_000)
    assert.ok(outcome.packets[0].microseconds >= 0 && outcome.packets[0].microseconds < 1_000_000)
})

test('core: second pcapng sample file', (): void => {
    const outcome: ParseOutcome = ParseFile('ipv4-one.pcapng')
    assert.strictEqual(outcome.packets.length, 1)
})

test('core: byte-by-byte chunking yields the identical result as a single write', (): void => {
    const whole: Buffer = readFileSync(FixtureCapturePath('GOOSE.pcap'))
    const single: ParseOutcome = ParseChunks([whole])
    const drip: ParseOutcome = ParseChunks(Array.from(whole, (byte: number): Buffer => Buffer.from([byte])))
    assert.strictEqual(drip.packets.length, single.packets.length)
    for (let i: number = 0; i < single.packets.length; i++) {
        assert.deepStrictEqual(drip.packets[i], single.packets[i])
    }
})

test('core: truncated pcap parses gracefully, no packets, no crash', (): void => {
    const outcome: ParseOutcome = ParseFile('invalid_pcap.pcap')
    assert.strictEqual(outcome.packets.length, 0)
    assert.strictEqual(outcome.error, null)
})

test('core: unknown magic number reports an error through onError', (): void => {
    const outcome: ParseOutcome = ParseChunks([Buffer.from('definitely not a capture file', 'ascii')])
    assert.strictEqual(outcome.packets.length, 0)
    assert.match(outcome.error!.message, /unknown magic number/)
})

test('core: nanosecond-resolution classic pcap converts fraction to microseconds', (): void => {
    const globalHeader: Buffer = Buffer.alloc(24)
    globalHeader.writeUInt32BE(0xa1b23c4d, 0)
    globalHeader.writeUInt16BE(2, 4)
    globalHeader.writeUInt16BE(4, 6)
    globalHeader.writeUInt32BE(262144, 16)
    globalHeader.writeUInt32BE(1, 20)
    const record: Buffer = Buffer.alloc(16 + 4)
    record.writeUInt32BE(1, 0)
    record.writeUInt32BE(1500, 4)
    record.writeUInt32BE(4, 8)
    record.writeUInt32BE(4, 12)
    record.fill(0xab, 16)
    const outcome: ParseOutcome = ParseChunks([Buffer.concat([globalHeader, record])])
    assert.strictEqual(outcome.packets.length, 1)
    assert.strictEqual(outcome.packets[0].seconds, 1)
    assert.strictEqual(outcome.packets[0].microseconds, 1)
    //full ns precision is preserved even though microseconds truncates it
    assert.strictEqual(outcome.packets[0].nanoseconds, 1500)
    assert.strictEqual(Buffer.from(outcome.packets[0].packet, 'base64').toString('hex'), 'abababab')
})

test('core: corrupt captured length reports an error instead of eating memory', (): void => {
    const globalHeader: Buffer = Buffer.alloc(24)
    globalHeader.writeUInt32LE(0xa1b2c3d4, 0)
    globalHeader.writeUInt16LE(2, 4)
    globalHeader.writeUInt16LE(4, 6)
    globalHeader.writeUInt32LE(262144, 16)
    globalHeader.writeUInt32LE(1, 20)
    const record: Buffer = Buffer.alloc(16)
    record.writeUInt32LE(1, 0)
    record.writeUInt32LE(0, 4)
    record.writeUInt32LE(0xf0000000, 8)
    record.writeUInt32LE(4, 12)
    const outcome: ParseOutcome = ParseChunks([Buffer.concat([globalHeader, record])])
    assert.strictEqual(outcome.packets.length, 0)
    assert.match(outcome.error!.message, /exceeds sane limit/)
})
