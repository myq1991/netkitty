import {test} from 'node:test'
import assert from 'node:assert'
import {AllPacketFixtureNames, LoadPacket} from '../lib/Fixtures'
import {Decode} from '../lib/RoundTrip'
import {toGolden, goldenExists, loadGolden, writeGolden, GoldenLayer} from '../lib/Golden'

// Regenerate the frozen snapshots with:  UPDATE_GOLDEN=1 node --test dist/tests/units/Golden.spec.js
const UPDATE: boolean = process.env.UPDATE_GOLDEN === '1'

// Every fixture's decode tree is pinned to a committed golden. This is the regression surface for
// DECODE SEMANTICS (values), which byte round-trip cannot see: a change that silently alters what a
// field decodes to fails here even though the bytes still round-trip.
test('golden: every fixture decodes to its frozen {data,errors} tree', async (): Promise<void> => {
    for (const name of AllPacketFixtureNames()) {
        // JSON-normalize the live tree so it matches the stored (JSON) form exactly (drops undefined).
        const golden: GoldenLayer[] = JSON.parse(JSON.stringify(toGolden(await Decode(LoadPacket(name).buffer))))
        if (UPDATE) {
            writeGolden(name, golden)
            continue
        }
        assert.ok(goldenExists(name), `no golden for '${name}' — run UPDATE_GOLDEN=1 to create it`)
        assert.deepStrictEqual(golden, loadGolden(name), `decode tree drifted from golden for '${name}'`)
    }
})
