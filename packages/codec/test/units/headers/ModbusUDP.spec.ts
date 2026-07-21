import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Modbus/UDP (udp:502) Read Holding Registers request — MBAP header + function code + data.
test('Modbus/UDP Read Holding Registers: MBAP + PDU + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('modbusudp/read-holding-registers').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'modbusudp'])
    const modbus: any = Layer(decoded, 'modbusudp').data
    assert.strictEqual(modbus.transactionId, 1)
    assert.strictEqual(modbus.protocolId, 0, 'Modbus protocol identifier')
    assert.strictEqual(modbus.length, 6)
    assert.strictEqual(modbus.unitId, 1)
    assert.strictEqual(modbus.functionCode, 3, 'Read Holding Registers')
    assert.strictEqual(modbus.data, '0000000a', 'start address 0x0000, quantity 0x000a')
})

// Crafting: build a Write Multiple Registers request (function 0x10) with the Length auto-computed from
// the data — confirm the MBAP Length lands correctly over UDP.
test('Modbus/UDP faithfully encodes a crafted request and auto-computes the MBAP Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 502}},
        {id: 'modbusudp', data: {
            transactionId: 0x1234, protocolId: 0, unitId: 1, functionCode: 0x10,
            data: '00000002040001000a' // start addr 0, qty 2, byte count 4, two register values
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'modbusudp'])
    const modbus: any = Layer(decoded, 'modbusudp').data
    assert.strictEqual(modbus.functionCode, 0x10, 'Write Multiple Registers')
    // Length = unit(1) + function(1) + data(9) = 11
    assert.strictEqual(modbus.length, 11, 'auto-computed MBAP Length')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive Length: an exception response (function code high bit set) supplies an explicit
// Length — it must be honored verbatim and round-trip.
test('Modbus/UDP exception response honors an explicit Length and round-trips', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.2', dip: '10.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 502, dstport: 40000}},
        {id: 'modbusudp', data: {transactionId: 1, protocolId: 0, length: 3, unitId: 1, functionCode: 0x83, data: '02'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const modbus: any = Layer(decoded, 'modbusudp').data
    assert.strictEqual(modbus.functionCode, 0x83, 'exception to Read Holding Registers (0x03 | 0x80)')
    assert.strictEqual(modbus.data, '02', 'exception code 0x02 (illegal data address)')
    assert.strictEqual(modbus.length, 3, 'supplied Length honored')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A UDP/502 payload that is not Modbus (non-zero Protocol Identifier) must fall through to raw.
test('Modbus/UDP rejects a non-zero Protocol Identifier on port 502 (falls through to raw)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 502}},
        {id: 'raw', data: {data: '0001ffff0006010300000001'}} // protocol identifier 0xffff, not Modbus
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'modbusudp'), 'non-zero protocol id must not be claimed as Modbus')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
})

test('Modbus/UDP truncated mid-PDU: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('modbusudp/read-holding-registers').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 2))
})
