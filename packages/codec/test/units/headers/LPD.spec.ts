import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// LPD / LPR (tcp:515) "Receive a printer job" command — 0x02 + queue name + LF, kept verbatim.
test('LPD receive-job: command metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('lpd/receive-job').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'lpd'])
    const lpd: any = Layer(decoded, 'lpd').data
    assert.strictEqual(lpd.command, 2, '0x02 Receive a printer job')
    assert.strictEqual(lpd.commandName, 'Receive a printer job')
    assert.strictEqual(lpd.operands, 'PostScript', 'operand line up to the LF')
    assert.strictEqual(lpd.message, '02506f73745363726970740a', 'whole payload kept verbatim')
})

// Crafting: a "Send queue state (short)" command (0x03 + queue + LF) round-trips byte-identically from
// the verbatim message; the display-only command/operands are derived from it on decode.
test('LPD faithfully encodes a crafted queue-state command from the verbatim message', async (): Promise<void> => {
    const message: string = '03' + Buffer.from('lp', 'latin1').toString('hex') + '0a'      // 0x03 "lp" LF
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40001, dstport: 515}},
        {id: 'lpd', data: {message: message}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'lpd'])
    const lpd: any = Layer(decoded, 'lpd').data
    assert.strictEqual(lpd.command, 3, 'Send queue state (short)')
    assert.strictEqual(lpd.commandName, 'Send queue state (short)')
    assert.strictEqual(lpd.operands, 'lp')
    assert.strictEqual(lpd.message, message, 'payload re-emitted verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: LPD is a port-bucket protocol with a command-code + LF guard. Binary garbage on port 515
// (invalid command code, no LF) must NOT be claimed as LPD (falls through to raw); and a truncated LPD
// message must survive decode without throwing.
test('LPD rejects non-LPD traffic on port 515, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40002, dstport: 515}},
        // command byte 0x02 but the rest is binary with no LF — not an LPD command line
        {id: 'raw', data: {data: '02ff00ffeeddccbbaa998877'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'lpd'), 'binary garbage on 515 must not be claimed as LPD')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('lpd/receive-job').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 3))
})
