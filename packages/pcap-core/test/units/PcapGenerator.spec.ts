import {test} from 'node:test'
import assert from 'node:assert'
import {PcapParserCore} from '../../src/PcapParserCore'
import {IPcapPacketInfo} from '../../src/interfaces/IPcapPacketInfo'
import {GeneratePCAP, GeneratePCAPHeader, GeneratePCAPData} from '../../src/PcapGenerator'

function ParseAll(buffer: Buffer): {format: string | null, packets: IPcapPacketInfo[]} {
    const packets: IPcapPacketInfo[] = []
    const parser: PcapParserCore = new PcapParserCore({onPacket: (info: IPcapPacketInfo): number => packets.push(info)})
    parser.write(buffer)
    parser.end()
    return {format: parser.format, packets: packets}
}

test('pcap generator: header magic is classic big-endian microsecond (a1b2c3d4)', (): void => {
    assert.strictEqual(GeneratePCAPHeader().toString('hex', 0, 4), 'a1b2c3d4')
})

test('pcap generator: frames + microsecond timestamps round-trip through the parser', (): void => {
    const frames: string[] = ['001122334455', 'aabbccddeeff00', 'ff']
    const pcap: Buffer = GeneratePCAP(frames.map((hex: string, i: number): {frameBase64Data: string, microsecond: {seconds: number, microseconds: number}} => ({
        frameBase64Data: Buffer.from(hex, 'hex').toString('base64'),
        microsecond: {seconds: 1700000000 + i, microseconds: 100 + i}
    })))
    const round: {format: string | null, packets: IPcapPacketInfo[]} = ParseAll(pcap)
    assert.strictEqual(round.format, 'pcap')
    assert.strictEqual(round.packets.length, frames.length)
    for (let i: number = 0; i < frames.length; i++) {
        assert.strictEqual(Buffer.from(round.packets[i].packet, 'base64').toString('hex'), frames[i])
        assert.strictEqual(round.packets[i].seconds, 1700000000 + i)
        assert.strictEqual(round.packets[i].microseconds, 100 + i)
    }
})

test('pcap generator: microsecond overflow carries into seconds (µs field stays 0..999999)', (): void => {
    const pcap: Buffer = GeneratePCAP([{frameBase64Data: Buffer.from('ab', 'hex').toString('base64'), microsecond: {seconds: 10, microseconds: 2500000}}])
    const round: {packets: IPcapPacketInfo[]} = ParseAll(pcap)
    //2,500,000 µs = 2.5 s → seconds 12, microseconds 500000
    assert.strictEqual(round.packets[0].seconds, 12)
    assert.strictEqual(round.packets[0].microseconds, 500000)
})

test('pcap generator: negative / fractional / NaN timestamps are clamped, never throw', (): void => {
    const frame: string = Buffer.from('cd', 'hex').toString('base64')
    const neg: {packets: IPcapPacketInfo[]} = ParseAll(GeneratePCAP([{frameBase64Data: frame, microsecond: {seconds: -3, microseconds: -7}}]))
    assert.strictEqual(neg.packets[0].seconds, 0)
    assert.strictEqual(neg.packets[0].microseconds, 0)
    const frac: {packets: IPcapPacketInfo[]} = ParseAll(GeneratePCAP([{frameBase64Data: frame, microsecond: {seconds: 5.9, microseconds: 12.4}}]))
    assert.strictEqual(frac.packets[0].seconds, 5)
    assert.strictEqual(frac.packets[0].microseconds, 12)
    const nan: {packets: IPcapPacketInfo[]} = ParseAll(GeneratePCAP([{frameBase64Data: frame, microsecond: {seconds: NaN, microseconds: NaN}}]))
    assert.strictEqual(nan.packets[0].seconds, 0)
    assert.strictEqual(nan.packets[0].microseconds, 0)
})

test('pcap generator: millisecond timestamp path splits into seconds + microseconds', (): void => {
    const pcap: Buffer = GeneratePCAPData({buffer: Buffer.from('ff', 'hex'), timestamp: 1500})
    //prepend a header so the parser can read the record
    const round: {packets: IPcapPacketInfo[]} = ParseAll(Buffer.concat([GeneratePCAPHeader(), pcap]))
    assert.strictEqual(round.packets[0].seconds, 1)
    assert.strictEqual(round.packets[0].microseconds, 500000)
})
