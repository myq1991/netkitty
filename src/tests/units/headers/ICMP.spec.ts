import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertLayers, Layer} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../lib/codec/types/CodecDecodeResult'

test('ICMPv4 echo request: field decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('icmp/echo-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'icmp'])
    const icmp: any = Layer(decoded, 'icmp').data
    assert.strictEqual(icmp.type, 8)
    assert.strictEqual(icmp.code, 0)
    assert.strictEqual(icmp.checksum, 21985)
    assert.strictEqual(icmp.ident, 24899)
    assert.strictEqual(icmp.seq, 0)
})

test('ICMPv4 echo reply: field decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('icmp/echo-reply').buffer)
    const icmp: any = Layer(decoded, 'icmp').data
    assert.strictEqual(icmp.type, 0)
    assert.strictEqual(icmp.code, 0)
})

test('ICMPv6: field decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('icmpv6/baseline').buffer)
    AssertLayers(decoded, ['eth', 'ipv6', 'icmpv6'])
    const icmpv6: any = Layer(decoded, 'icmpv6').data
    assert.strictEqual(icmpv6.type, 134, 'router advertisement')
    assert.strictEqual(icmpv6.code, 0)
    assert.strictEqual(icmpv6.checksum, 11184)
})
