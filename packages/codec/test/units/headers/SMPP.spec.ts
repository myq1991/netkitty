import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// SMPP 3.4 (tcp:2775) bind_transceiver — 16-byte header (command_length/command_id/command_status/
// sequence_number) + command-specific body kept verbatim.
test('SMPP bind_transceiver: header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('smpp/bind-transceiver').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'smpp'])
    const smpp: any = Layer(decoded, 'smpp').data
    assert.strictEqual(smpp.commandLength, 40, 'total PDU length incl 16-byte header')
    assert.strictEqual(smpp.commandId, 0x00000009, 'bind_transceiver')
    assert.strictEqual(smpp.commandStatus, 0, 'ESME_ROK')
    assert.strictEqual(smpp.sequenceNumber, 1, 'sequence number')
    // system_id "SMPP3TEST"\0, password "secret08"\0, system_type ""\0, interface_version 0x34, addr_ton/npi 0, address_range ""\0
    assert.strictEqual(smpp.body, '534d50503354455354007365637265743038000034000000', 'bind_transceiver body verbatim')
})

// Crafting: a minimal bind_transceiver_resp (command_id 0x80000009, the response bit set) with an empty
// body and the command_length auto-computed from the (empty) body — must re-encode byte-identically, and
// the unclamped uint32 command_id proves a high-bit (response) operation survives round-trip.
test('SMPP faithfully encodes a crafted response PDU and auto-computes command_length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.20', dip: '192.0.2.10', protocol: 6}},
        {id: 'tcp', data: {srcport: 2775, dstport: 51001}},
        {id: 'smpp', data: {commandId: 0x80000009, commandStatus: 0, sequenceNumber: 1}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'smpp'])
    const smpp: any = Layer(decoded, 'smpp').data
    assert.strictEqual(smpp.commandId, 0x80000009, 'response bit preserved (unclamped uint32)')
    assert.strictEqual(smpp.commandLength, 16, 'auto-computed command_length = 16 (header only, empty body)')
    assert.strictEqual(smpp.body, '', 'empty body')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive command_length: a crafted PDU supplies an explicit command_length — it must be
// honored verbatim (not overwritten by the derived value) so a PDU that carries any length round-trips.
test('SMPP honors an explicitly supplied command_length (does not derive over it)', async (): Promise<void> => {
    // 1-byte body => derived length would be 17; supply 17 explicitly and confirm it is honored.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 51001, dstport: 2775}},
        {id: 'smpp', data: {commandLength: 17, commandId: 0x00000015, commandStatus: 0, sequenceNumber: 7, body: '00'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const smpp: any = Layer(decoded, 'smpp').data
    assert.strictEqual(smpp.commandId, 0x00000015, 'enquire_link')
    assert.strictEqual(smpp.commandLength, 17, 'supplied command_length honored')
    assert.strictEqual(smpp.body, '00', 'body verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/2775 payload shorter than the 16-byte header must NOT be claimed as SMPP (falls
// through to raw); and a truncated SMPP PDU must survive decode without throwing.
test('SMPP requires the full 16-byte header, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 2775}},
        // 5 bytes of non-signature data — below the 16-byte header minimum, must not be claimed as SMPP
        {id: 'raw', data: {data: 'deadbeef00'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'smpp'), 'sub-header payload must not be claimed as SMPP')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('smpp/bind-transceiver').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})

// Protocol-specific edge: two SMPP PDUs pipelined in one TCP segment. The first PDU is bounded by its
// command_length, so its body does NOT swallow the trailing PDU; the trailing bytes fall through to raw
// (a leaf header advances only over its own PDU and does not re-match itself, matching the
// length-bounded-TCP-payload precedent). Both directions round-trip byte-for-byte.
test('SMPP pipelining: the first PDU is bounded by its command_length; the trailing PDU falls through to raw', async (): Promise<void> => {
    const firstBody: string = '00'                                        // 1-byte body => command_length 17
    const first: string = '00000011' + '00000015' + '00000000' + '00000009' + firstBody  // enquire_link, seq 9
    const second: string = '00000010' + '80000015' + '00000000' + '00000009'              // enquire_link_resp, 16 bytes
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 2775, dstport: 51001}},
        {id: 'raw', data: {data: first + second}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'smpp', 'raw'])
    const smpp: any = Layer(decoded, 'smpp').data
    assert.strictEqual(smpp.commandLength, 17, 'first PDU length')
    assert.strictEqual(smpp.body, firstBody, 'body bounded by command_length — trailing PDU not swallowed')
    assert.strictEqual((Layer(decoded, 'raw').data as any).data, second, 'trailing PDU left as raw')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Regression (was a decode→encode throw): a PDU whose command_length field is below the 16-byte header
// (0..15) must decode AND re-encode without throwing — the length is honored verbatim, not rejected by
// Ajv at the encode entry. Previously the schema's minimum:16 made validate() throw on re-encode.
test('SMPP never-throws: a sub-16 command_length round-trips without an Ajv throw', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 2775, dstport: 51001}},
        // command_length 5 (< the 16-byte header), command_id/status/seq filling the required 16 bytes
        {id: 'raw', data: {data: '00000005' + '00000015' + '00000000' + '00000009'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const smpp: any = Layer(decoded, 'smpp').data
    assert.strictEqual(smpp.commandLength, 5, 'sub-16 command_length honored verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect, no Ajv throw')
})
