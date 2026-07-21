import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// VRRP v2 Advertisement (RFC 3768) over IP protocol 112 — the fixed 8-byte header + virtual IP list.
test('VRRP v2 Advertisement: header + address list + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('vrrp/advert-v2').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'vrrp'])
    const vrrp: any = Layer(decoded, 'vrrp').data
    assert.strictEqual(vrrp.version, 2, 'VRRP v2')
    assert.strictEqual(vrrp.type, 1, 'Advertisement')
    assert.strictEqual(vrrp.vrid, 1)
    assert.strictEqual(vrrp.priority, 100)
    assert.strictEqual(vrrp.count, 1)
    assert.strictEqual(vrrp.authType, 0)
    assert.strictEqual(vrrp.adverInt, 1, 'v2 advertisement interval in whole seconds')
    assert.deepStrictEqual(vrrp.addresses, ['192.168.1.1'])
})

// Crafting: build a v3 Advertisement (RFC 5798) — bytes 4-5 are the reserved nibble + 12-bit Max
// Advertisement Interval (centiseconds), and there is no v2 auth data. Confirm the version-specific
// fields write the right bytes and the frame round-trips.
test('VRRP v3 Advertisement round-trips (version-specific bytes 4-5 = Max Adver Int)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:12', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '224.0.0.18', protocol: 112, ttl: 255}},
        {id: 'vrrp', data: {
            version: 3, type: 1, vrid: 5, priority: 200, count: 2,
            rsvd: 0, maxAdverInt: 100, checksum: 0x1234,
            addresses: ['10.0.0.1', '10.0.0.2']
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'vrrp'])
    const vrrp: any = Layer(decoded, 'vrrp').data
    assert.strictEqual(vrrp.version, 3, 'VRRP v3')
    assert.strictEqual(vrrp.maxAdverInt, 100, 'Max Adver Int (centiseconds)')
    assert.strictEqual(vrrp.count, 2)
    assert.deepStrictEqual(vrrp.addresses, ['10.0.0.1', '10.0.0.2'])
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// v2 with Auth Type 1 (Simple Text Password) carries 8 trailing bytes of authentication data after the
// address list — kept verbatim.
test('VRRP v2 with Simple Text Password auth data round-trips (auth data verbatim)', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:00:00:12', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.1', dip: '224.0.0.18', protocol: 112, ttl: 255}},
        {id: 'vrrp', data: {
            version: 2, type: 1, vrid: 1, priority: 100, count: 1,
            authType: 1, adverInt: 1, checksum: 0x0000,
            addresses: ['192.168.1.1'], authData: '7061737377643132' // "passwd12"
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const vrrp: any = Layer(decoded, 'vrrp').data
    assert.strictEqual(vrrp.authType, 1)
    assert.strictEqual(vrrp.authData, '7061737377643132', 'auth data preserved verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// A malformed / future VRRP version (not 2 or 3) must still round-trip byte-for-byte: bytes 4-5 have no
// v2/v3 owner, so they are captured verbatim (decode never fails + malformed lossless round-trip).
test('VRRP unknown version preserves bytes 4-5 verbatim (malformed lossless round-trip)', async (): Promise<void> => {
    // version nibble 5, type 1, vrid 1, prio 100, bytes4-5 = aabb, checksum b952, addr 192.168.1.1
    const frame: Buffer = Buffer.from('00000000000000000000000008004500002096aa4000ff7085af7f000001e000001251016401aabbb952c0a80101', 'hex')
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(frame)
    const vrrp: any = Layer(decoded, 'vrrp').data
    assert.strictEqual(vrrp.version, 5, 'unknown version decoded best-effort')
    assert.strictEqual(vrrp.reserved45, 'aabb', 'bytes 4-5 preserved verbatim for an unknown version')
})

test('VRRP truncated mid-address-list: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('vrrp/advert-v2').buffer
    await AssertDecodeSurvives(full.subarray(0, 40))
})
