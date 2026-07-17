import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, Decode} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../lib/codec/types/CodecDecodeResult'

test('802.1Q VLAN tag: field decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('goose/vlan-structure').buffer)
    const vlan: any = Layer(decoded, 'vlan').data
    assert.strictEqual(vlan.priority, 5)
    assert.strictEqual(vlan.dei, false)
    assert.strictEqual(vlan.id, 204)
    assert.strictEqual(vlan.etherType, '88b8')
})

test('Synthetic minimal VLAN+GOOSE frame: decode survives with accumulated errors', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertDecodeSurvives(LoadPacket('vlan/goose').buffer)
    AssertLayers(decoded, ['eth', 'vlan', 'goose'])
    const goose: CodecDecodeResult = Layer(decoded, 'goose')
    assert.ok(goose.errors.length > 0, 'missing PDU fields must be reported as errors')
})

// This synthetic frame carries a goosePdu whose body is not valid GOOSE ASN.1, so every
// mandatory child field is "Not Found". The raw-fallback surfaces the unparsed bytes as a
// visible goosePdu.raw field and re-emits them verbatim, so even this malformed frame now
// round-trips byte-for-byte.
test('Synthetic minimal VLAN+GOOSE frame: unparsed goosePdu surfaced as raw', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await Decode(LoadPacket('vlan/goose').buffer)
    const goose: any = Layer(decoded, 'goose')
    assert.ok(goose.data.goosePdu.raw, 'the un-parseable goosePdu bytes must be visible as goosePdu.raw')
})

test('Synthetic minimal VLAN+GOOSE frame: byte-perfect round-trip via raw fallback', async (): Promise<void> => {
    await AssertRoundTrip(LoadPacket('vlan/goose').buffer)
})
