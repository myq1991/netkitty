import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'

// Real NTPv3 server response (mode 4) captured from a local chrony server. RFC 5905 §7.3.
test('NTP server response: field decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ntp/response').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'ntp'])
    const ntp: any = Layer(decoded, 'ntp').data
    assert.strictEqual(ntp.li, 0, 'leap indicator')
    assert.strictEqual(ntp.vn, 3, 'version 3')
    assert.strictEqual(ntp.mode, 4, 'mode 4 = server')
    assert.strictEqual(ntp.stratum, 8)
    assert.strictEqual(ntp.poll, 0)
    assert.strictEqual(ntp.precision, -25, 'precision is a signed power-of-two exponent')
    assert.strictEqual(ntp.rootDelay, 0)
    assert.strictEqual(ntp.rootDispersion, 0)
    assert.strictEqual(ntp.refId, '7f7f0101')
    assert.strictEqual(ntp.refTimestamp, 'ee0791cdb865d992')
    assert.strictEqual(ntp.originTimestamp, '0000000000000000')
    assert.strictEqual(ntp.receiveTimestamp, 'ee0791cf6144e1fd')
    assert.strictEqual(ntp.transmitTimestamp, 'ee0791cf614a447c')
})

// Negative / crafting: encode is a faithful executor — reserved/invalid field values that still fit
// their bit width (mode 6 = reserved, version 7 = undefined, reserved stratum 200) are emitted as
// given and survive a byte round-trip. This is the deliberately-malformed-packet capability.
test('NTP faithfully encodes and round-trips a crafted packet with reserved/invalid field values', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 123, dstport: 40000}},
        {id: 'ntp', data: {
            li: 3, vn: 7, mode: 6, stratum: 200, poll: 15, precision: -1, refId: 'deadbeef',
            refTimestamp: '1122334455667788', originTimestamp: '0000000000000000',
            receiveTimestamp: '0000000000000000', transmitTimestamp: 'ffffffffffffffff'
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const ntp: any = Layer(decoded, 'ntp').data
    assert.strictEqual(ntp.li, 3)
    assert.strictEqual(ntp.vn, 7)
    assert.strictEqual(ntp.mode, 6)
    assert.strictEqual(ntp.stratum, 200)
    assert.strictEqual(ntp.poll, 15)
    assert.strictEqual(ntp.precision, -1)
    assert.strictEqual(ntp.refId, 'deadbeef')
    assert.strictEqual(ntp.transmitTimestamp, 'ffffffffffffffff')
})

test('NTP truncated mid-timestamp: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('ntp/response').buffer
    // Cut into the final timestamps (drop the last 12 bytes).
    await AssertDecodeSurvives(full.subarray(0, full.length - 12))
})
