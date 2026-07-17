import {test} from 'node:test'
import assert from 'node:assert'
import {Readable} from 'node:stream'
import {LoadPacket, FixtureCapturePath} from '../lib/Fixtures'
import {PcapReader} from '../../lib/pcap/PcapReader'
import {PcapParser} from '../../lib/pcap/PcapParser'
import {IPcapPacketInfo} from '../../lib/pcap/interfaces/IPcapPacketInfo'

/**
 * Read every packet of a capture file (resolves on 'done', rejects on 'error')
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
 * Parse a capture from an in-memory buffer with PcapParser directly
 */
async function ParseBuffer(buffer: Buffer): Promise<IPcapPacketInfo[]> {
    return new Promise((resolve, reject): void => {
        const parser: PcapParser = PcapParser.parse(Readable.from([buffer]) as any)
        const packets: IPcapPacketInfo[] = []
        parser.on('packet', (pcapPacketInfo: IPcapPacketInfo): number => packets.push(pcapPacketInfo))
        parser.once('error', reject)
        parser.once('end', (): void => resolve(packets))
    })
}

test('classic pcap: reads all packets, first packet bytes match extracted fixture', async (): Promise<void> => {
    const packets: IPcapPacketInfo[] = await ReadCaptureFile(FixtureCapturePath('GOOSE.pcap'))
    assert.strictEqual(packets.length, 8)
    const firstPacketHex: string = Buffer.from(packets[0].packet, 'base64').toString('hex')
    assert.strictEqual(firstPacketHex, LoadPacket('goose/baseline').hex)
    assert.ok(packets[0].seconds > 0)
})

test('classic pcap: larger session file (105-packet IEC104 capture)', async (): Promise<void> => {
    const packets: IPcapPacketInfo[] = await ReadCaptureFile(FixtureCapturePath('iec104.pcap'))
    assert.strictEqual(packets.length, 105)
})

test('pcapng: reads packets, bytes match extracted fixture, timestamps resolved', async (): Promise<void> => {
    const packets: IPcapPacketInfo[] = await ReadCaptureFile(FixtureCapturePath('tcp-1.pcapng'))
    assert.strictEqual(packets.length, 1)
    const packetHex: string = Buffer.from(packets[0].packet, 'base64').toString('hex')
    assert.strictEqual(packetHex, LoadPacket('tcp/baseline').hex)
    assert.ok(packets[0].seconds > 1_500_000_000, 'pcapng 64-bit timestamp must resolve to a plausible epoch time')
    assert.ok(packets[0].microseconds >= 0 && packets[0].microseconds < 1_000_000)
})

test('pcapng: second sample file', async (): Promise<void> => {
    const packets: IPcapPacketInfo[] = await ReadCaptureFile(FixtureCapturePath('ipv4-one.pcapng'))
    assert.strictEqual(packets.length, 1)
})

test('pcapng: readPacketData() returns the same bytes the parser reported', async (): Promise<void> => {
    const filename: string = FixtureCapturePath('tcp-1.pcapng')
    const packets: IPcapPacketInfo[] = await ReadCaptureFile(filename)
    const reader: PcapReader = new PcapReader({filename: filename, watch: false})
    const data: Buffer = await reader.readPacketData(packets[0])
    assert.strictEqual(data.toString('hex'), LoadPacket('tcp/baseline').hex)
})

test('truncated pcap (packet body cut off): parses gracefully, no packets, no crash', async (): Promise<void> => {
    const packets: IPcapPacketInfo[] = await ReadCaptureFile(FixtureCapturePath('invalid_pcap.pcap'))
    assert.strictEqual(packets.length, 0)
})

test('unknown magic number: emits error instead of crashing', async (): Promise<void> => {
    await assert.rejects(
        ParseBuffer(Buffer.from('definitely not a capture file', 'ascii')),
        /unknown magic number/
    )
})

test('nanosecond-resolution classic pcap: fraction converted to microseconds', async (): Promise<void> => {
    //Hand-crafted big-endian nanosecond pcap: magic a1b23c4d, one 4-byte packet at t=1s+1500ns
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
    const packets: IPcapPacketInfo[] = await ParseBuffer(Buffer.concat([globalHeader, record]))
    assert.strictEqual(packets.length, 1)
    assert.strictEqual(packets[0].seconds, 1)
    assert.strictEqual(packets[0].microseconds, 1, '1500ns must convert to 1µs, not be misread as 1500µs')
    assert.strictEqual(Buffer.from(packets[0].packet, 'base64').toString('hex'), 'abababab')
})

test('corrupt pcap record header (absurd captured length): emits error instead of eating memory', async (): Promise<void> => {
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
    await assert.rejects(
        ParseBuffer(Buffer.concat([globalHeader, record])),
        /exceeds sane limit/
    )
})
