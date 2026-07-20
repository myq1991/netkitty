import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// TACACS+ (RFC 8907, tcp:49) Authentication START — the 12-byte header + verbatim (encrypted) body.
test('TACACS+ Authentication START: 12-byte header + body + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tacacs/authen-start').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tacacs'])
    const tacacs: any = Layer(decoded, 'tacacs').data
    assert.strictEqual(tacacs.version.major, 12, 'major version 0xc (TACACS+ signature)')
    assert.strictEqual(tacacs.version.minor, 0, 'minor version 0')
    assert.strictEqual(tacacs.type, 1, 'Authentication')
    assert.strictEqual(tacacs.seqNo, 1)
    assert.strictEqual(tacacs.flags, 0)
    assert.strictEqual(tacacs.sessionId, 0x12345678, 'big-endian session id')
    assert.strictEqual(tacacs.length, 8, 'length counts only the body bytes')
    assert.strictEqual(tacacs.body, 'deadbeefcafef00d', 'encrypted body kept verbatim')
})

// Crafting: build an Authorization REQUEST with the Length auto-computed from the body — confirm the
// big-endian Length lands correctly and the packet round-trips.
test('TACACS+ faithfully encodes a crafted packet and auto-computes the Length', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 49}},
        {id: 'tacacs', data: {
            version: {major: 12, minor: 1}, type: 2, seqNo: 1, flags: 0x01,
            sessionId: 0xdeadbeef, body: '00112233445566778899'
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'tacacs'])
    const tacacs: any = Layer(decoded, 'tacacs').data
    assert.strictEqual(tacacs.version.major, 12)
    assert.strictEqual(tacacs.version.minor, 1)
    assert.strictEqual(tacacs.type, 2, 'Authorization')
    assert.strictEqual(tacacs.flags, 0x01, 'UNENCRYPTED_FLAG')
    assert.strictEqual(tacacs.sessionId, 0xdeadbeef, 'big-endian session id')
    assert.strictEqual(tacacs.length, 10, 'auto-computed from the 10-byte body')
    assert.strictEqual(tacacs.body, '00112233445566778899')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A TCP/49 payload whose major-version nibble is not 0xc must fall through to raw.
test('TACACS+ rejects a non-0xc major version on port 49 (falls through to raw)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '10.0.0.1', dip: '10.0.0.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 49}},
        {id: 'raw', data: {data: '01010100123456780000000800'}} // major nibble 0x0, not 0xc
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'tacacs'), 'must not claim a non-TACACS+ payload')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')
})

test('TACACS+ truncated mid-body: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('tacacs/authen-start').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 3))
})
