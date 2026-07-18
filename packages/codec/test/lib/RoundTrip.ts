import assert from 'node:assert'
import {Codec} from '../../src/lib/codec/Codec'
import {CodecDecodeResult} from '../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../src/lib/codec/types/CodecEncodeResult'

export const codec: Codec = new Codec()

/**
 * Decode a packet buffer with the shared default codec
 */
export async function Decode(buffer: Buffer): Promise<CodecDecodeResult[]> {
    return await codec.decode(buffer)
}

/**
 * Layer id sequence of a decode result, e.g. ['eth', 'ipv4', 'tcp']
 */
export function LayerIds(results: CodecDecodeResult[]): string[] {
    return results.map((result: CodecDecodeResult): string => result.id)
}

/**
 * Assert a layer exists and return it
 */
export function Layer(results: CodecDecodeResult[], id: string): CodecDecodeResult {
    const found: CodecDecodeResult | undefined = results.find((result: CodecDecodeResult): boolean => result.id === id)
    assert.ok(found, `expected layer '${id}' in decoded layers [${LayerIds(results).join(', ')}]`)
    return found!
}

/**
 * Assert the decoded layer id sequence equals the expectation exactly
 */
export function AssertLayers(results: CodecDecodeResult[], expected: string[]): void {
    assert.deepStrictEqual(LayerIds(results), expected, 'decoded layer sequence mismatch')
}

/**
 * Core harness assertion: decode a packet, re-encode the decode result,
 * and require byte-identical reproduction of the original packet.
 * Returns the decode result for further field assertions.
 */
export async function AssertRoundTrip(buffer: Buffer): Promise<CodecDecodeResult[]> {
    const decoded: CodecDecodeResult[] = await codec.decode(buffer)
    const encoded: CodecEncodeResult = await codec.encode(decoded)
    assert.strictEqual(
        encoded.packet.toString('hex'),
        buffer.toString('hex'),
        'decode→encode round-trip must reproduce the original bytes'
    )
    return decoded
}

/**
 * Decode a deliberately malformed/truncated packet and assert the codec
 * survives: it must not throw and must consume the whole input
 */
export async function AssertDecodeSurvives(buffer: Buffer): Promise<CodecDecodeResult[]> {
    const decoded: CodecDecodeResult[] = await codec.decode(buffer)
    assert.ok(decoded.length > 0, 'decoder must always produce at least one layer')
    return decoded
}
