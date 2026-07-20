import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// rsync daemon (tcp:873) server greeting "@RSYNCD: 31.0\n". The whole payload is kept verbatim, so it
// round-trips byte-for-byte, and the greeting first line is parsed into display-only metadata.
test('rsync greeting: first-line metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('rsync/greeting').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'rsync'])
    const rsync: any = Layer(decoded, 'rsync').data
    assert.strictEqual(rsync.isGreeting, true, 'a @RSYNCD: greeting line')
    assert.strictEqual(rsync.version, '31.0', 'protocol version token')
    assert.strictEqual(rsync.message, '405253594e43443a2033312e300a', 'raw payload kept verbatim ("@RSYNCD: 31.0\\n")')
})

// A crafted "@RSYNCD: OK\n" status line (sent by the server to accept a module): the greeting signature
// is present, so version parses to the status word "OK"; the message re-emits verbatim so it round-trips.
test('rsync parses a @RSYNCD status word and re-emits verbatim', async (): Promise<void> => {
    const okHex: string = Buffer.from('@RSYNCD: OK\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 873, dstport: 50218}},
        {id: 'rsync', data: {message: okHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'rsync'])
    const rsync: any = Layer(decoded, 'rsync').data
    assert.strictEqual(rsync.isGreeting, true, 'a @RSYNCD: line')
    assert.strictEqual(rsync.version, 'OK', 'status word after @RSYNCD:')
    assert.strictEqual(rsync.message, okHex, 'message kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// After the handshake the connection turns to a binary multiplexed stream: a non-greeting segment on
// port 873 is still captured verbatim (isGreeting=false, no version) and round-trips byte-for-byte. The
// leading bytes are a fake mux tag with no protocol content signature.
test('rsync keeps a binary (non-greeting) segment verbatim', async (): Promise<void> => {
    const binHex: string = '070000200102030405060708090a0b0c'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.20', dip: '192.0.2.10', protocol: 6}},
        {id: 'tcp', data: {srcport: 50218, dstport: 873}},
        {id: 'rsync', data: {message: binHex}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'rsync'])
    const rsync: any = Layer(decoded, 'rsync').data
    assert.strictEqual(rsync.isGreeting, false, 'binary frame is not a greeting')
    assert.strictEqual(rsync.version, '', 'no version for a non-greeting segment')
    assert.strictEqual(rsync.message, binHex, 'binary payload kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A truncated rsync greeting (cut mid-line) must decode without throwing and re-encode without throwing.
test('rsync truncated mid-greeting: decode survives AND re-encodes', async (): Promise<void> => {
    const full: Buffer = LoadPacket('rsync/greeting').buffer
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 6))
    // The decode output must always be re-encodable (schema-valid), even truncated.
    await codec.encode(decoded)
})
