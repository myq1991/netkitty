import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/types/CodecEncodeResult'

// The Login Request data segment: two NUL-terminated login key=value pairs (62 bytes).
const LOGIN_DATA: string = '496e69746961746f724e616d653d69716e2e323032302d30312e636f6d2e6578616d706c653a696e69740053657373696f6e547970653d4e6f726d616c00'

// iSCSI (tcp:3260) Login Request — 48-byte Basic Header Segment + a padded login-key data segment.
test('iSCSI Login Request: BHS + data segment + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('iscsi/login-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'iscsi'])
    const iscsi: any = Layer(decoded, 'iscsi').data
    assert.strictEqual(iscsi.opcode, 3, 'Login Request')
    assert.strictEqual(iscsi.immediate, true, 'Immediate bit set')
    assert.strictEqual(iscsi.reserved, 0, 'byte-0 reserved bit')
    assert.strictEqual(iscsi.final, true, 'Final/Transit bit set')
    assert.strictEqual(iscsi.opcodeSpecificFlags, 7, 'byte-1 flags: C=0, CSG=1, NSG=3')
    assert.strictEqual(iscsi.totalAHSLength, 0, 'no AHS')
    assert.strictEqual(iscsi.dataSegmentLength, 62, 'DataSegmentLength')
    assert.strictEqual(iscsi.lun, '4000013700000000', 'ISID + TSIH')
    assert.strictEqual(iscsi.initiatorTaskTag, 'abcdef01', 'Initiator Task Tag')
    assert.strictEqual(iscsi.dataSegment, LOGIN_DATA, 'login key=value pairs kept verbatim (unpadded)')
})

// honor-else-derive DataSegmentLength: a crafted NOP-Out (opcode 0x00) supplies a data segment but no
// DataSegmentLength — it must be derived from the actual data, and the 4-byte-alignment padding
// re-emitted, so the PDU round-trips byte-for-byte.
test('iSCSI derives the DataSegmentLength and pads the data segment when not supplied', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 3260}},
        // 5-byte data segment => DataSegmentLength derived = 5, padded with 3 zero bytes to 8.
        {id: 'iscsi', data: {opcode: 0x00, initiatorTaskTag: '00000001', dataSegment: 'a1b2c3d4e5'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'iscsi'])
    const iscsi: any = Layer(decoded, 'iscsi').data
    assert.strictEqual(iscsi.opcode, 0, 'NOP-Out')
    assert.strictEqual(iscsi.dataSegmentLength, 5, 'derived from the actual data segment length')
    assert.strictEqual(iscsi.dataSegment, 'a1b2c3d4e5', 'data segment kept verbatim (unpadded)')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// honor-else-derive: a crafted PDU supplies an explicit DataSegmentLength — it must be honored (written
// verbatim into bytes 5-7), not overwritten by the derived value.
test('iSCSI honors an explicitly supplied DataSegmentLength', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 3260}},
        {id: 'iscsi', data: {opcode: 0x01, dataSegmentLength: 4, initiatorTaskTag: 'cafebabe', dataSegment: 'deadbeef'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const iscsi: any = Layer(decoded, 'iscsi').data
    assert.strictEqual(iscsi.opcode, 1, 'SCSI Command')
    assert.strictEqual(iscsi.dataSegmentLength, 4, 'supplied DataSegmentLength honored')
    assert.strictEqual(iscsi.dataSegment, 'deadbeef', 'data segment kept verbatim')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: a TCP/3260 payload shorter than the 48-byte BHS must NOT be claimed as iSCSI (falls through
// to raw); and a truncated Login Request must survive decode without throwing.
test('iSCSI rejects a sub-48-byte payload on port 3260, and truncation survives', async (): Promise<void> => {
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.0.2.1', dip: '192.0.2.2', protocol: 6}},
        {id: 'tcp', data: {srcport: 3260, dstport: 40000}},
        // 8-byte TCP payload — fewer than the 48 bytes a BHS needs.
        {id: 'raw', data: {data: '0102030405060708'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'iscsi'), 'a sub-48-byte payload must not be claimed as iSCSI')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    // Truncating the well-formed Login Request part-way through its data segment must not throw.
    const full: Buffer = LoadPacket('iscsi/login-request').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 20))
    // Truncating mid-BHS must not throw either.
    await AssertDecodeSurvives(full.subarray(0, 70))
})
