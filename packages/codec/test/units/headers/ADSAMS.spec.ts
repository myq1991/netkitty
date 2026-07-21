import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Beckhoff ADS/AMS (tcp:48898) ADS Read request — 6-byte AMS/TCP header (reserved + length) + 32-byte
// AMS header (all little-endian) + Read data (index group / offset / length). Byte-perfect round-trip.
test('ADS/AMS Read request: AMS/TCP + AMS header + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('adsams/read-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'adsams'])
    const ams: any = Layer(decoded, 'adsams').data
    assert.strictEqual(ams.reserved, '0000', 'AMS/TCP reserved')
    assert.strictEqual(ams.length, 44, 'AMS/TCP length = 32-byte AMS header + 12-byte data (LE)')
    assert.strictEqual(ams.targetNetId, 'c0a800010101', 'target AmsNetId 192.168.0.1.1.1')
    assert.strictEqual(ams.targetPort, 851, 'target AmsPort 851 (LE)')
    assert.strictEqual(ams.sourceNetId, 'c0a800020101', 'source AmsNetId 192.168.0.2.1.1')
    assert.strictEqual(ams.sourcePort, 33025, 'source AmsPort 33025 (LE)')
    assert.strictEqual(ams.commandId, 2, 'Command Id 2 (Read)')
    assert.strictEqual(ams.stateFlags, 4, 'State Flags 0x0004 (ADS command, request)')
    assert.strictEqual(ams.dataLength, 12, 'Data Length 12 (LE)')
    assert.strictEqual(ams.errorCode, 0, 'Error Code 0')
    assert.strictEqual(ams.invokeId, 1, 'Invoke Id 1 (LE)')
    assert.strictEqual(ams.data, '204000000000000004000000', 'Read: index group 0x4020, offset 0, length 4')
})

// Crafting: a Read request with only the data supplied — both length fields (AMS/TCP Length and AMS
// Data Length) auto-computed from the data, and every LE field re-encoded byte-identically.
test('ADS/AMS auto-computes AMS/TCP Length and Data Length from the data', async (): Promise<void> => {
    const data: string = '2040000000000000' + '04000000'          // index group 0x4020, offset 0, length 4
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.2', dip: '192.168.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 48898}},
        {id: 'adsams', data: {
            targetNetId: 'c0a800010101', targetPort: 851,
            sourceNetId: 'c0a800020101', sourcePort: 33025,
            commandId: 2, stateFlags: 4, invokeId: 7, data: data
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'adsams'])
    const ams: any = Layer(decoded, 'adsams').data
    assert.strictEqual(ams.commandId, 2, 'Read')
    assert.strictEqual(ams.dataLength, 12, 'auto-computed Data Length = 12 (data bytes)')
    assert.strictEqual(ams.length, 44, 'auto-computed AMS/TCP Length = 32 + 12')
    assert.strictEqual(ams.invokeId, 7, 'Invoke Id round-trips (LE)')
    assert.strictEqual(ams.data, data, 'data preserved')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted packet supplies explicit (lying) length fields — they must be honored
// verbatim, not overwritten by the derived values, so a message carrying any length round-trips.
test('ADS/AMS honors explicitly supplied Length / Data Length (does not derive over them)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.1', dip: '192.168.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 48898, dstport: 40000}},
        // ReadState (command 4) response: state flags 0x0005 (response + ADS command), a 4-byte
        // result. Length/Data Length supplied explicitly and honored.
        {id: 'adsams', data: {
            reserved: '0000', length: 36,
            targetNetId: 'c0a800020101', targetPort: 33025,
            sourceNetId: 'c0a800010101', sourcePort: 851,
            commandId: 4, stateFlags: 5, dataLength: 4, errorCode: 0, invokeId: 7,
            data: '00000000'
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const ams: any = Layer(decoded, 'adsams').data
    assert.strictEqual(ams.commandId, 4, 'ReadState')
    assert.strictEqual(ams.length, 36, 'supplied AMS/TCP Length honored')
    assert.strictEqual(ams.dataLength, 4, 'supplied Data Length honored')
    assert.strictEqual(ams.stateFlags, 5, 'response + ADS command')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: an AMS-looking TCP payload on a port other than 48898 must NOT be claimed as ADS/AMS
// (port-bucketed selection, no content heuristic); and a truncated ADS/AMS message survives decode.
test('ADS/AMS is not claimed off port 48898, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.2', dip: '192.168.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 12345}},
        {id: 'raw', data: {data: '00002c000000c0a8000101015303c0a800020101018102000400' +
            '0c0000000000000001000000204000000000000004000000'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'adsams'), 'off-port must not be ADS/AMS')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('adsams/read-request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 5))
})

// Protocol-specific edge: two ADS/AMS messages pipelined in one TCP segment. The first is bounded by
// its Data Length so its data does NOT swallow the trailing message; the trailing bytes fall through to
// raw (a leaf header advances only over its own message and its match() requires the previous layer to
// be tcp, so it does not re-match itself). Round-trips byte-for-byte.
test('ADS/AMS pipelining: first message bounded by Data Length; trailing message falls through to raw', async (): Promise<void> => {
    const one: string = '00002c000000c0a8000101015303c0a800020101018102000400' +
        '0c0000000000000001000000204000000000000004000000'          // 50-byte AMS/TCP message
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.0.2', dip: '192.168.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 48898}},
        {id: 'raw', data: {data: one + one}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'adsams', 'raw'])
    const ams: any = Layer(decoded, 'adsams').data
    assert.strictEqual(ams.dataLength, 12, 'first message Data Length')
    assert.strictEqual(ams.data, '204000000000000004000000', 'data bounded by Data Length — trailing message not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, one, 'trailing message left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
