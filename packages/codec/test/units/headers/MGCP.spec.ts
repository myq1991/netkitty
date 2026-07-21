import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Real-shaped MGCP CRCX (CreateConnection) command on UDP port 2427 (RFC 3435). The whole message —
// command line, parameter lines and embedded SDP — is kept verbatim, so it round-trips byte-for-byte,
// and the command line is parsed into display-only metadata.
test('MGCP CRCX command: first-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('mgcp/crcx').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'mgcp'])
    const mgcp: any = Layer(decoded, 'mgcp').data
    assert.strictEqual(mgcp.isResponse, false, 'a command line')
    assert.strictEqual(mgcp.verb, 'CRCX')
    assert.strictEqual(mgcp.transactionId, '1200')
    assert.strictEqual(mgcp.endpoint, 'aaln/1@rgw.example.net')
    assert.strictEqual(mgcp.version, 'MGCP 1.0')
    assert.strictEqual(mgcp.responseCode, 0, 'commands have no response code')
    assert.strictEqual(mgcp.comment, '')
})

// A crafted 200 OK response: the response line is parsed into responseCode/comment, and because the
// message is re-emitted verbatim the whole packet round-trips byte-for-byte.
test('MGCP 200 response: response-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    // "200 1200 OK\r\nI: FDE234C8\r\n\r\n"
    const respHex: string = '3230302031323030204f4b0d0a493a2046444532333443380d0a0d0a'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 2427, dstport: 2727}},
        {id: 'mgcp', data: {message: respHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'mgcp'])
    const mgcp: any = Layer(decoded, 'mgcp').data
    assert.strictEqual(mgcp.isResponse, true, 'a response line')
    assert.strictEqual(mgcp.verb, '', 'responses have no verb')
    assert.strictEqual(mgcp.responseCode, 200)
    assert.strictEqual(mgcp.transactionId, '1200')
    assert.strictEqual(mgcp.message, respHex, 'message kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'))
})

// Non-MGCP traffic on UDP port 2427 (no verb, no 3-digit response code) must NOT be claimed as MGCP —
// it falls through to raw and round-trips. Uses unsigned binary junk that no content heuristic claims.
test('MGCP does not claim non-MGCP traffic on port 2427', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 2427, dstport: 2427}},
        {id: 'raw', data: {data: '9c8b7a6d5e4f00112233'}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'mgcp'), 'binary junk on 2427 is not MGCP')
})

// A truncated MGCP message (cut mid-message) must decode without throwing and re-encode without throwing.
test('MGCP truncated mid-message: decode survives AND re-encodes', async (): Promise<void> => {
    const full: Buffer = LoadPacket('mgcp/crcx').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 60))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)
})
