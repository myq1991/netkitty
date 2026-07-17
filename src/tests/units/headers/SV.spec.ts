import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {codec, Layer, AssertRoundTrip} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../lib/codec/types/CodecDecodeResult'

// This real IEC 61850-9-2 frame carries a savPdu whose BER cannot be parsed.
// Decode must never throw (error accumulation), must SURFACE the unparsed bytes as a
// visible svPdu.raw field (so a capture analyst sees the malformed region instead of a
// deceptively-empty PDU), and must reproduce the original bytes on re-encode via that raw.
test('SV baseline: unparseable Sampled Values frame decodes without throwing', async (): Promise<void> => {
    await assert.doesNotReject(async (): Promise<void> => {
        void await codec.decode(LoadPacket('sv/baseline').buffer)
    })
})

test('SV baseline: unparsed savPdu is surfaced as a visible raw field', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('sv/baseline').buffer)
    const sv: any = Layer(decoded, 'sv')
    assert.ok(sv.data.svPdu.raw, 'the un-parseable savPdu bytes must be visible as svPdu.raw')
    assert.ok(sv.errors.some((e: any): boolean => e.path === 'svPdu'), 'the parse failure must be recorded as an error')
})

test('SV baseline: raw fallback reproduces the original bytes on re-encode', async (): Promise<void> => {
    await AssertRoundTrip(LoadPacket('sv/baseline').buffer)
})

// BUG 5 (REAL): smpMod decode reads the WRONG tag.
//   IEC61850SampledValues.ts:274 decode looks up tag 0x86 for smpMod, but 0x86 is smpRate's
//   tag; smpMod's tag is 0x88 (which the encoder at :335 correctly writes). As a result the
//   decoded smpMod always equals the decoded smpRate and the true smpMod (0x88) is ignored.
// The fixture is a synthesized, self-consistent SV frame (so it decodes past the SV
// "Invalid length" bug) carrying smpRate(0x86)=4096 and smpMod(0x88)=2. Correct behaviour:
// decoded smpMod must be 2, not 4096.
test('BUG5 SV smpMod must be decoded from tag 0x88, not smpRate tag 0x86', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('sv/smpmod').buffer)
    const asdu: any = (Layer(decoded, 'sv').data as any).svPdu.seqASDU[0]
    assert.strictEqual(asdu.smpRate, 4096, 'smpRate (tag 0x86) sanity')
    assert.strictEqual(asdu.smpMod, 2, 'smpMod must come from tag 0x88 (=2), not mirror smpRate (=4096)')
})
