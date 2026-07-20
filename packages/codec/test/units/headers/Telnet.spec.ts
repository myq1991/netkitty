import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Real busybox telnetd initial option negotiation (RFC 854) on TCP port 23: IAC WILL ECHO, IAC WILL
// SGA, IAC DO NAWS, then the shell prompt. The whole payload is kept verbatim (byte-perfect), and the
// leading IAC command run is parsed into display-only metadata {isNegotiation, commands}.
test('Telnet negotiation: leading IAC commands + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('telnet/negotiate').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'telnet'])
    const telnet: any = Layer(decoded, 'telnet').data
    assert.strictEqual(telnet.isNegotiation, true, 'the payload opens with an IAC byte')
    // FF FB 01 — IAC WILL ECHO
    assert.strictEqual(telnet.commands[0].command, 251, 'first command is WILL')
    assert.strictEqual(telnet.commands[0].option, 1, 'first option is ECHO')
    // FF FD 1F — IAC DO NAWS (window size, option 31)
    assert.strictEqual(telnet.commands[2].command, 253, 'third command is DO')
    assert.strictEqual(telnet.commands[2].option, 31, 'third option is NAWS')
    assert.strictEqual(telnet.commands.length, 3, 'three leading IAC commands, then the prompt data')
})

// A plain data payload (no IAC) on port 23 is still Telnet — the whole byte stream is kept verbatim and
// round-trips byte-for-byte, and the display metadata report no commands and no negotiation.
test('Telnet data-only payload: verbatim, no commands', async (): Promise<void> => {
    const payload: string = Buffer.from('login: ', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 23, dstport: 49812}},
        {id: 'telnet', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'telnet'])
    const telnet: any = Layer(decoded, 'telnet').data
    assert.strictEqual(telnet.isNegotiation, false, 'no leading IAC → not a negotiation')
    assert.deepStrictEqual(telnet.commands, [], 'no IAC commands in plain data')
    assert.strictEqual(telnet.message, payload, 'the byte stream is kept verbatim')
})

// The verbatim guarantee: the negotiation is re-emitted byte-identical from the `message` field, never
// reconstructed from the parsed commands metadata.
test('Telnet negotiation re-encodes byte-identical (verbatim)', async (): Promise<void> => {
    const fixture: {buffer: Buffer, hex: string} = LoadPacket('telnet/negotiate')
    const decoded: CodecDecodeResult[] = await codec.decode(fixture.buffer)
    const telnet: any = Layer(decoded, 'telnet').data
    assert.strictEqual(telnet.message, 'fffb01fffb03fffd1f2f202320', 'message holds the whole payload verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), fixture.hex)
})

// Port confinement (no heuristicFallback): an IAC-looking payload on a non-23 port must NOT be claimed as
// Telnet — it falls through to raw. And a truncated payload on port 23 must decode without throwing.
test('Telnet is confined to port 23; truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49812, dstport: 9999}}, // not port 23
        {id: 'raw', data: {data: 'fffb01fffb03'}} // looks like Telnet negotiation, but off-port
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'telnet'), 'IAC bytes off port 23 must not be claimed by Telnet')

    // A negotiation cut mid-command on port 23 must decode without throwing and remain re-encodable.
    const full: Buffer = LoadPacket('telnet/negotiate').buffer
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 3))
    await codec.encode(survived)
})

// A subnegotiation (IAC SB <opt> …params… IAC SE) round-trips byte-for-byte, and its leading SB command
// is parsed into the display metadata. Here: IAC SB TERMINAL-TYPE IS "ANSI" IAC SE.
test('Telnet subnegotiation round-trips byte-perfect', async (): Promise<void> => {
    // FF FA 18 00 41 4E 53 49 FF F0 — SB TERMINAL-TYPE(24) IS(0) "ANSI" SE
    const payload: string = 'fffa1800414e5349fff0'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49812, dstport: 23}},
        {id: 'telnet', data: {message: payload}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'telnet'])
    const telnet: any = Layer(decoded, 'telnet').data
    assert.strictEqual(telnet.isNegotiation, true, 'opens with IAC')
    assert.strictEqual(telnet.message, payload, 'the subnegotiation bytes are kept verbatim')
    assert.strictEqual(telnet.commands[0].command, 250, 'SB subnegotiation begin')
    assert.strictEqual(telnet.commands[0].option, 24, 'subnegotiation option is TERMINAL-TYPE')
    assert.strictEqual(telnet.commands.length, 1, 'the whole SB…SE is one parsed command')
})
