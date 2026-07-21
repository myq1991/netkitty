import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// Git Smart Protocol (git://, tcp:9418) — a git-daemon request pkt-line. The whole segment payload is
// kept verbatim as `message`; only the first pkt-line is parsed into display-only metadata.
test('Git upload-pack request: verbatim message + parsed first pkt-line + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('git/upload-pack').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'git'])
    const git: any = Layer(decoded, 'git').data
    // "0032" = 50-byte pkt-line (prefix counts itself), payload = git-upload-pack /project.git\0host=example.com\0
    assert.strictEqual(git.firstPktLineLength, 50, 'declared pkt-line length (incl 4-char prefix)')
    assert.strictEqual(git.firstCommand, 'git-upload-pack /project.git', 'service command + repo path, up to first NUL')
    assert.strictEqual(
        git.message,
        '303033326769742d75706c6f61642d7061636b202f70726f6a6563742e67697400686f73743d6578616d706c652e636f6d00',
        'entire segment payload kept verbatim'
    )
})

// Crafting: a flush-pkt ("0000") is a valid, empty git pkt-line. The verbatim message must re-encode
// byte-identically, and the parsed length is 0 with an empty command.
test('Git faithfully encodes a crafted flush-pkt and parses length 0 / empty command', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 9418}},
        {id: 'git', data: {message: '30303030'}}                       // "0000" flush-pkt
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'git'])
    const git: any = Layer(decoded, 'git').data
    assert.strictEqual(git.firstPktLineLength, 0, 'flush-pkt declares length 0')
    assert.strictEqual(git.firstCommand, '', 'flush-pkt carries no command')
    assert.strictEqual(git.message, '30303030', 'message kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/9418 payload whose first 4 bytes are NOT ASCII hex digits (no pkt-line length prefix)
// must NOT be claimed as git (falls through to raw); and a truncated git segment must survive decode
// without throwing.
test('Git rejects a non-hex-prefix payload on port 9418, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 9418}},
        // high bytes: not ASCII hex digits, so not a pkt-line length prefix (and no registered signature)
        {id: 'raw', data: {data: 'ce8fa7d29b3c'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'git'), 'non-hex-prefix payload must not be claimed as git')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    // Truncate inside the git payload (lower layers intact): must not throw.
    const full: Buffer = LoadPacket('git/upload-pack').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 4))
})

// Protocol-specific edge: a pkt-line whose declared length exceeds the bytes actually present (a
// truncated / crafted-short pkt-line). Decode must not throw, must keep the truncated bytes verbatim,
// and re-encode byte-for-byte — the declared length parses but the command is clamped to the bytes seen.
test('Git tolerates a pkt-line whose declared length exceeds the captured bytes', async (): Promise<void> => {
    // "0032" claims 50 bytes but only "git" (3 bytes) follow — 7 payload bytes total.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.10', dip: '192.0.2.20', protocol: 6}},
        {id: 'tcp', data: {srcport: 51000, dstport: 9418}},
        {id: 'git', data: {message: '30303332676974'}}                 // "0032git"
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const git: any = Layer(decoded, 'git').data
    assert.strictEqual(git.firstPktLineLength, 50, 'declared length parsed even though under-filled')
    assert.strictEqual(git.firstCommand, 'git', 'command clamped to the bytes actually present')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})
