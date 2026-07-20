import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// Real OpenSSH server identification banner (RFC 4253) on TCP port 22. The whole line is kept verbatim,
// so it round-trips byte-for-byte, and the line is parsed into display-only metadata.
test('SSH identification: banner metadata + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ssh/ident').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'ssh'])
    const ssh: any = Layer(decoded, 'ssh').data
    assert.strictEqual(ssh.isIdentification, true, 'the payload begins with "SSH-"')
    assert.strictEqual(ssh.protoVersion, '2.0')
    assert.ok(ssh.softwareVersion.includes('OpenSSH'), `softwareVersion "${ssh.softwareVersion}" carries the server string`)
    assert.strictEqual(ssh.identString, 'SSH-2.0-OpenSSH_10.3')
})

// The verbatim guarantee: the identification line is re-emitted byte-identical from the `message` field,
// never reconstructed from the parsed metadata.
test('SSH identification line re-encodes byte-identical (verbatim)', async (): Promise<void> => {
    const fixture: {buffer: Buffer, hex: string} = LoadPacket('ssh/ident')
    const decoded: CodecDecodeResult[] = await codec.decode(fixture.buffer)
    const ssh: any = Layer(decoded, 'ssh').data
    const expectedMessage: string = Buffer.from('SSH-2.0-OpenSSH_10.3\r\n', 'latin1').toString('hex')
    assert.strictEqual(ssh.message, expectedMessage, 'message holds the whole banner verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), fixture.hex)
})

// A crafted Binary Packet Protocol message (a cleartext KEXINIT-style frame) on port 22: packet_length
// and padding_length are parsed as structured fields, and payload+padding is kept verbatim as `data`,
// so the whole packet round-trips byte-for-byte.
test('SSH binary packet: structured length/padding + verbatim data round-trips', async (): Promise<void> => {
    // packet_length = 12 = 1 (padding_length byte) + 11 (payload + padding); data is those 11 bytes.
    const data: string = 'aabbccddeeff0011223344'
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49876, dstport: 22}},
        {id: 'ssh', data: {isIdentification: false, packetLength: 12, paddingLength: 6, data: data}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'ssh'])
    const ssh: any = Layer(decoded, 'ssh').data
    assert.strictEqual(ssh.isIdentification, false, 'not an identification line')
    assert.strictEqual(ssh.packetLength, 12)
    assert.strictEqual(ssh.paddingLength, 6)
    assert.strictEqual(ssh.data, data, 'payload + padding kept verbatim')
    assert.strictEqual(ssh.message, '', 'no identification line for a binary packet')
})

// Port confinement (no heuristicFallback): an "SSH-" banner on a non-22 port must NOT be claimed as SSH —
// it falls through to raw. And a truncated banner on port 22 must decode without throwing.
test('SSH is confined to port 22; truncation survives', async (): Promise<void> => {
    const bannerHex: string = Buffer.from('SSH-2.0-OpenSSH_9.6\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 49876, dstport: 9999}}, // not port 22
        {id: 'raw', data: {data: bannerHex}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'raw'])
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'ssh'), 'an SSH banner off port 22 must not be claimed by SSH')

    // A banner cut mid-line on port 22 must decode without throwing and remain re-encodable.
    const full: Buffer = LoadPacket('ssh/ident').buffer
    const survived: CodecDecodeResult[] = await AssertDecodeSurvives(full.subarray(0, full.length - 8))
    await codec.encode(survived)
})

// An SSH-1.99 banner (a 2.0 server that also speaks the legacy 1.x protocol) parses protoVersion "1.99".
test('SSH-1.99 banner parses protoVersion "1.99"', async (): Promise<void> => {
    const bannerHex: string = Buffer.from('SSH-1.99-TestServer\r\n', 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 22, dstport: 49876}},
        {id: 'ssh', data: {isIdentification: true, message: bannerHex}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'ssh'])
    const ssh: any = Layer(decoded, 'ssh').data
    assert.strictEqual(ssh.isIdentification, true)
    assert.strictEqual(ssh.protoVersion, '1.99')
    assert.strictEqual(ssh.softwareVersion, 'TestServer')
})
