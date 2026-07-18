import {test} from 'node:test'
import assert from 'node:assert'
import {AllPacketFixtureNames, LoadPacket} from '../lib/Fixtures'
import {codec} from '../lib/RoundTrip'

// Corpus-wide invariant: decode → encode must reproduce the original bytes for EVERY
// packet fixture, well-formed or malformed. Malformed frames whose internal structure the
// codec cannot parse (e.g. sv/baseline, vlan/goose) are held to the same standard via the
// raw-fallback (unparsed regions are preserved as a visible `raw` field and re-emitted).
test('every packet fixture survives a byte-perfect decode→encode round-trip', async (): Promise<void> => {
    const names: string[] = AllPacketFixtureNames()
    assert.ok(names.length > 0, 'expected at least one packet fixture')
    const mismatches: string[] = []
    for (const name of names) {
        const original: Buffer = LoadPacket(name).buffer
        const encoded = await codec.encode(await codec.decode(original))
        if (encoded.packet.toString('hex') !== original.toString('hex')) {
            mismatches.push(`${name} (orig ${original.length}B, encoded ${encoded.packet.length}B)`)
        }
    }
    assert.deepStrictEqual(mismatches, [], `these fixtures did not round-trip byte-for-byte:\n  ${mismatches.join('\n  ')}`)
})
