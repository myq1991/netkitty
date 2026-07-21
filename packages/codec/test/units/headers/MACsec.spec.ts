import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

const SECURED: string = 'a1b2c3d4e5f60718293a4b5c6d7e8f900102030405060708090a0b0c0d0e0f101112131415161718'
const ICV: string = 'cafebabedeadbeef0011223344556677'

// MACsec (IEEE 802.1AE, EtherType 0x88E5) — an encrypted frame carrying an SCI. SecTAG (14 bytes with
// SCI) + 40-byte secured data + 16-byte ICV. Byte-perfect round-trip and SecTAG field decode.
test('MACsec with SCI: SecTAG decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('macsec/sci').buffer)
    AssertLayers(decoded, ['eth', 'macsec'])
    const macsec: any = Layer(decoded, 'macsec').data
    assert.strictEqual(macsec.version, 0, 'V')
    assert.strictEqual(macsec.es, 0, 'ES')
    assert.strictEqual(macsec.sc, 1, 'SC set → SCI present')
    assert.strictEqual(macsec.scb, 0, 'SCB')
    assert.strictEqual(macsec.encryption, 1, 'E set → encrypted')
    assert.strictEqual(macsec.changed, 1, 'C')
    assert.strictEqual(macsec.an, 0, 'AN')
    assert.strictEqual(macsec.shortLength, 40, 'SL = secured-data length (< 48)')
    assert.strictEqual(macsec.packetNumber, 1, 'PN')
    assert.strictEqual(macsec.sci, '0011223344550001', 'SCI = system id + port')
    assert.strictEqual(macsec.securedData, SECURED, '40-byte opaque secured data kept verbatim')
    assert.strictEqual(macsec.icv, ICV, 'trailing 16-byte ICV kept verbatim')
})

// Craft a MACsec frame WITHOUT an SCI (SC bit clear → 6-byte SecTAG): the secured data / ICV must start
// 8 octets earlier. encode → decode → re-encode must be byte-identical.
test('MACsec without SCI: crafted 6-byte SecTAG round-trips byte-for-byte', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:03', smac: 'aa:bb:cc:dd:ee:ff', etherType: '88e5'}},
        {id: 'macsec', data: {
            version: 0, es: 0, sc: 0, scb: 0, encryption: 1, changed: 0, an: 1,
            shortLength: 20, packetNumber: 5,
            securedData: '00112233445566778899aabbccddeeff01020304',
            icv: '00000000000000000000000000000000'
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'macsec'])
    const macsec: any = Layer(decoded, 'macsec').data
    assert.strictEqual(macsec.sc, 0, 'SC clear')
    assert.strictEqual(macsec.sci, '', 'no SCI when SC is clear')
    assert.strictEqual(macsec.an, 1, 'AN preserved in the low 2 bits')
    assert.strictEqual(macsec.packetNumber, 5, 'PN')
    assert.strictEqual(macsec.securedData, '00112233445566778899aabbccddeeff01020304', 'secured data at 6-octet offset')
    assert.strictEqual(macsec.icv, '00000000000000000000000000000000', 'ICV')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Crafting with SCI via the encoder: the SC bit set forces the 8-byte SCI into the SecTAG, shifting the
// secured data + ICV. A faithful executor carries the ICV as-is (never recomputed).
test('MACsec faithfully encodes a crafted frame with an SCI', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:03', smac: 'aa:bb:cc:dd:ee:ff', etherType: '88e5'}},
        {id: 'macsec', data: {
            sc: 1, encryption: 1, an: 2,
            shortLength: 0, packetNumber: 4294967295,
            sci: 'aabbccddeeff0002',
            securedData: 'deadbeefcafebabe',
            icv: '112233445566778899aabbccddeeff00'
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const macsec: any = Layer(decoded, 'macsec').data
    assert.strictEqual(macsec.sc, 1)
    assert.strictEqual(macsec.an, 2, 'AN = 2')
    assert.strictEqual(macsec.packetNumber, 4294967295, 'max PN honored')
    assert.strictEqual(macsec.sci, 'aabbccddeeff0002', 'SCI preserved')
    assert.strictEqual(macsec.securedData, 'deadbeefcafebabe')
    assert.strictEqual(macsec.icv, '112233445566778899aabbccddeeff00', 'ICV carried as-is')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a truncated MACsec frame (SecTAG cut mid-way) must survive decode without throwing, and a
// frame with only the SecTAG (no secured data / ICV) must still decode and round-trip.
test('MACsec truncation survives and a SecTAG-only frame round-trips', async (): Promise<void> => {
    const full: Buffer = LoadPacket('macsec/sci').buffer
    // Cut inside the secured data so the SecTAG + partial payload remain.
    await AssertDecodeSurvives(full.subarray(0, 30))

    // A frame whose payload is exactly a 6-byte SecTAG (SC clear, no SCI, no data, no ICV).
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:80:c2:00:00:03', smac: 'aa:bb:cc:dd:ee:ff', etherType: '88e5'}},
        {id: 'macsec', data: {sc: 0, encryption: 0, an: 0, shortLength: 0, packetNumber: 7, securedData: '', icv: ''}}
    ])
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(packet)
    const macsec: any = Layer(decoded, 'macsec').data
    assert.strictEqual(macsec.packetNumber, 7, 'PN of the SecTAG-only frame')
    assert.strictEqual(macsec.securedData, '', 'no secured data')
    assert.strictEqual(macsec.icv, '', 'no ICV')
})
