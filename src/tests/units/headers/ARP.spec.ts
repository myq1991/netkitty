import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../lib/codec/types/CodecDecodeResult'

test('ARP baseline: field decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('arp/baseline').buffer)
    const eth: any = Layer(decoded, 'eth').data
    assert.strictEqual(eth.etherType, '0806')
    assert.strictEqual(eth.dmac, 'ff:ff:ff:ff:ff:ff')
    const arp: any = Layer(decoded, 'arp').data
    assert.strictEqual(arp.opcode, 1)
    assert.strictEqual(arp.hardware.type, 1)
    assert.strictEqual(arp.hardware.size, 6)
    assert.strictEqual(arp.protocol.type, '0800')
    assert.strictEqual(arp.protocol.size, 4)
    assert.strictEqual(arp.sender.mac, 'cb:d3:87:fa:59:2f')
    assert.strictEqual(arp.sender.ipv4, '171.81.157.212')
    assert.strictEqual(arp.target.ipv4, '108.247.1.1')
})

test('ARP edit workflow: decode → modify opcode → encode → re-decode', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('arp/baseline').buffer)
    const arp: any = Layer(decoded, 'arp').data
    arp.opcode = 2
    const encoded = await codec.encode(decoded)
    const redecoded: CodecDecodeResult[] = await codec.decode(encoded.packet)
    assert.strictEqual((Layer(redecoded, 'arp').data as any).opcode, 2)
})

test('ARP encode rejects out-of-range values via schema validation', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('arp/baseline').buffer)
    const arp: any = Layer(decoded, 'arp').data
    arp.hardware.type = 70000
    await assert.rejects(async (): Promise<void> => void await codec.encode(decoded))
})

test('ARP truncated to ethernet header only: decode survives', async (): Promise<void> => {
    await AssertDecodeSurvives(LoadPacket('arp/baseline').buffer.subarray(0, 14))
})

// BUG #4 (REAL): encoding ARP mutates protocol.type from a hex string into a number.
// ARP.ts:80-88 reads protocol.type as hex '0800', computes HexToUInt16('0800') = 2048, writes the
// bytes 08 00 (correct), but then does `this.instance.protocol.type.setValue(protoType)` with the
// NUMBER 2048. Because encode reuses the caller's data object in place (Ajv validate does not
// clone), the decoded result's protocol.type is now the number 2048.
// Re-encoding the SAME decoded result feeds 2048 back through HexToUInt16, i.e. parseInt('2048', 16)
// = 0x2048 = 8264, so the second encode writes the bytes 20 48 instead of 08 00. Encoding must be
// idempotent: encoding a decode result twice must yield identical wire bytes.
test('ARP protocol.type must survive a second encode (idempotent encoding)', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket('arp/baseline').buffer)
    const first = await codec.encode(decoded)
    const second = await codec.encode(decoded)
    assert.strictEqual(
        second.packet.toString('hex'),
        first.packet.toString('hex'),
        'encoding a decode result twice must produce identical bytes'
    )
    const redecoded: CodecDecodeResult[] = await codec.decode(second.packet)
    assert.strictEqual((Layer(redecoded, 'arp').data as any).protocol.type, '0800',
        'protocol.type must stay 0x0800 (IPv4) after re-encoding, not become 0x2048')
})

// RFC 826: hardware type is an unsigned 16-bit field. A value >= 0x8000 must decode as a
// positive number (it was previously read signed via BufferToInt16, yielding a negative value).
test('ARP hardware type 0x8000 decodes as unsigned 32768 and round-trips', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('arp/arp-htype-high').buffer)
    const arp: any = Layer(decoded, 'arp').data
    assert.strictEqual(arp.hardware.type, 32768, 'htype 0x8000 must be unsigned 32768, not negative')
})
