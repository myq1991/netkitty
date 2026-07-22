import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync} from 'node:fs'
import {PcapParserCore} from '../../src/PcapParserCore'
import {IPcapPacketInfo} from '../../src/interfaces/IPcapPacketInfo'
import {GeneratePcapng, GeneratePcapngInputPacket, GeneratePcapngSectionHeader, GeneratePcapngInterfaceDescription} from '../../src/PcapngGenerator'
import {FixtureCapturePath} from '../lib/Fixtures'

/** Parse a whole capture buffer with PcapParserCore, returning every emitted packet info */
function ParseAll(buffer: Buffer): {format: string | null, packets: IPcapPacketInfo[]} {
    const packets: IPcapPacketInfo[] = []
    const parser: PcapParserCore = new PcapParserCore({onPacket: (info: IPcapPacketInfo): number => packets.push(info)})
    parser.write(buffer)
    parser.end()
    return {format: parser.format, packets: packets}
}

test('pcapng generator: file round-trips through the parser as pcapng with identical frames', (): void => {
    const source: {packets: IPcapPacketInfo[]} = ParseAll(readFileSync(FixtureCapturePath('iec104.pcap')))
    assert.ok(source.packets.length > 0)

    const input: GeneratePcapngInputPacket[] = source.packets.map((info: IPcapPacketInfo): GeneratePcapngInputPacket => ({
        frameBase64Data: info.packet,
        microsecond: {seconds: info.seconds, microseconds: info.microseconds}
    }))
    const pcapng: Buffer = GeneratePcapng(input)

    const round: {format: string | null, packets: IPcapPacketInfo[]} = ParseAll(pcapng)
    assert.strictEqual(round.format, 'pcapng')
    assert.strictEqual(round.packets.length, source.packets.length)
    for (let i: number = 0; i < source.packets.length; i++) {
        assert.strictEqual(round.packets[i].packet, source.packets[i].packet, `frame ${i} bytes`)
        assert.strictEqual(round.packets[i].seconds, source.packets[i].seconds, `frame ${i} seconds`)
        assert.strictEqual(round.packets[i].microseconds, source.packets[i].microseconds, `frame ${i} microseconds`)
    }
})

test('pcapng generator: leading bytes are a valid Section Header Block, all blocks 32-bit aligned', (): void => {
    const pcapng: Buffer = GeneratePcapng([{frameBase64Data: Buffer.from('001122334455', 'hex').toString('base64'), microsecond: {seconds: 1, microseconds: 2}}])
    assert.strictEqual(pcapng.toString('hex', 0, 4), '0a0d0d0a') //SHB block type
    assert.strictEqual(pcapng.readUInt32LE(8), 0x1a2b3c4d) //byte-order magic (little-endian)
    assert.strictEqual(pcapng.length % 4, 0)
})

test('pcapng generator: an odd-length frame is padded so the packet block stays 32-bit aligned', (): void => {
    //7-byte frame → EPB data area padded to 8 → whole file length divisible by 4, parser recovers 7 bytes
    const frame: Buffer = Buffer.from('00112233445566', 'hex')
    const pcapng: Buffer = GeneratePcapng([{frameBase64Data: frame.toString('base64'), microsecond: {seconds: 0, microseconds: 0}}])
    assert.strictEqual(pcapng.length % 4, 0)
    const round: {packets: IPcapPacketInfo[]} = ParseAll(pcapng)
    assert.strictEqual(round.packets.length, 1)
    assert.strictEqual(Buffer.from(round.packets[0].packet, 'base64').toString('hex'), '00112233445566')
})

test('pcapng generator: an empty packet list produces just SHB + IDB and no packets', (): void => {
    const pcapng: Buffer = GeneratePcapng([])
    assert.strictEqual(pcapng.length, GeneratePcapngSectionHeader().length + GeneratePcapngInterfaceDescription().length)
    const round: {format: string | null, packets: IPcapPacketInfo[]} = ParseAll(pcapng)
    assert.strictEqual(round.format, 'pcapng')
    assert.strictEqual(round.packets.length, 0)
})

test('pcapng generator: a microsecond timestamp survives the 64-bit tick encoding', (): void => {
    const pcapng: Buffer = GeneratePcapng([{frameBase64Data: Buffer.from('ff', 'hex').toString('base64'), microsecond: {seconds: 1700000000, microseconds: 123456}}])
    const round: {packets: IPcapPacketInfo[]} = ParseAll(pcapng)
    assert.strictEqual(round.packets[0].seconds, 1700000000)
    assert.strictEqual(round.packets[0].microseconds, 123456)
})

test('pcapng generator: a timestamp beyond the 32-bit seconds wall still round-trips exactly', (): void => {
    const seconds: number = 4294967296 //2^32, past the UInt32 wall (year 2106)
    const pcapng: Buffer = GeneratePcapng([{frameBase64Data: Buffer.from('ab', 'hex').toString('base64'), microsecond: {seconds: seconds, microseconds: 7}}])
    const round: {packets: IPcapPacketInfo[]} = ParseAll(pcapng)
    assert.strictEqual(round.packets[0].seconds, seconds)
    assert.strictEqual(round.packets[0].microseconds, 7)
})

test('pcapng generator: negative / fractional / NaN timestamps are clamped, never throw or corrupt', (): void => {
    const frame: string = Buffer.from('cd', 'hex').toString('base64')
    //negative → clamped to 0 (not wrapped to a huge unsigned tick count)
    const neg: {packets: IPcapPacketInfo[]} = ParseAll(GeneratePcapng([{frameBase64Data: frame, microsecond: {seconds: -1, microseconds: -5}}]))
    assert.strictEqual(neg.packets.length, 1)
    assert.strictEqual(neg.packets[0].seconds, 0)
    assert.strictEqual(neg.packets[0].microseconds, 0)
    //fractional seconds → floored, and generation does not throw (which would abort the whole batch)
    const frac: {packets: IPcapPacketInfo[]} = ParseAll(GeneratePcapng([{frameBase64Data: frame, microsecond: {seconds: 10.9, microseconds: 3.7}}]))
    assert.strictEqual(frac.packets[0].seconds, 10)
    assert.strictEqual(frac.packets[0].microseconds, 3)
    //NaN → treated as 0
    const nan: {packets: IPcapPacketInfo[]} = ParseAll(GeneratePcapng([{frameBase64Data: frame, microsecond: {seconds: NaN, microseconds: NaN}}]))
    assert.strictEqual(nan.packets[0].seconds, 0)
    assert.strictEqual(nan.packets[0].microseconds, 0)
})
