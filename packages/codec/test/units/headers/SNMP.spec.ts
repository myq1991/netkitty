import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'

// Real SNMP v2c get-request (sysName.0) captured from net-snmp snmpget. RFC 1157 / RFC 3416, ASN.1 BER.
test('SNMP get-request: BER decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('snmp/get-request').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'snmp'])
    const snmp: any = Layer(decoded, 'snmp').data
    assert.strictEqual(snmp.version, 1, 'v2c')
    assert.strictEqual(snmp.community, 'public')
    assert.strictEqual(snmp.pduType, 0xa0, 'get-request context tag')
    assert.strictEqual(snmp.requestId, 1137294592)
    assert.strictEqual(snmp.errorStatus, 0)
    assert.strictEqual(snmp.variableBindings.length, 1)
    assert.strictEqual(snmp.variableBindings[0].oid, '1.3.6.1.2.1.1.5.0', 'sysName.0')
    assert.strictEqual(snmp.variableBindings[0].valueType, 0x05, 'NULL value in a request')
    assert.strictEqual(snmp.variableBindings[0].value, '')
})

// Real SNMP v2c get-response (sysUpTime.0 = TimeTicks). Exercises a non-OctetString BER value type.
test('SNMP get-response: TimeTicks value kept verbatim + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('snmp/get-response').buffer)
    const snmp: any = Layer(decoded, 'snmp').data
    assert.strictEqual(snmp.pduType, 0xa2, 'get-response context tag')
    assert.strictEqual(snmp.requestId, 1064999220)
    assert.strictEqual(snmp.variableBindings[0].oid, '1.3.6.1.2.1.1.3.0', 'sysUpTime.0')
    assert.strictEqual(snmp.variableBindings[0].valueType, 0x43, 'TimeTicks')
    assert.strictEqual(snmp.variableBindings[0].value, '012d', 'raw value bytes = 301 ticks')
})

// Negative / crafting: encode is a faithful executor. Craft a set-request with an INTEGER value and an
// enterprise OID whose arcs exceed 127 (311 → base-128 multi-byte) — exercises the OID encoder and a
// non-trivial request-id, and must round-trip byte-for-byte through decode→encode.
test('SNMP faithfully encodes a crafted set-request with a large-arc OID and an integer value', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 17}},
        {id: 'udp', data: {srcport: 40000, dstport: 161}},
        {id: 'snmp', data: {
            version: 1, community: 'private', pduType: 0xa3, requestId: 305419896, errorStatus: 0, errorIndex: 0,
            variableBindings: [{oid: '1.3.6.1.4.1.311.1.1', valueType: 0x02, value: '2a'}]
        }}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const snmp: any = Layer(decoded, 'snmp').data
    assert.strictEqual(snmp.community, 'private')
    assert.strictEqual(snmp.pduType, 0xa3, 'set-request')
    assert.strictEqual(snmp.requestId, 305419896)
    assert.strictEqual(snmp.variableBindings[0].oid, '1.3.6.1.4.1.311.1.1', 'large arc 311 survives base-128 round-trip')
    assert.strictEqual(snmp.variableBindings[0].valueType, 0x02)
    assert.strictEqual(snmp.variableBindings[0].value, '2a')
    // Re-encode reproduces the exact same bytes.
    const {packet: reencoded}: {packet: Buffer} = await codec.encode(decoded)
    assert.strictEqual(reencoded.toString('hex'), packet.toString('hex'))
})

// SNMPv1 Trap-PDU (0xa4) has a body shape (enterprise/agent-addr/generic/specific/timestamp/varbinds)
// that differs from the RFC 3416 request/response PDUs. It must NOT be misparsed as the standard shape;
// its body is kept verbatim (pduRaw) so it round-trips byte-for-byte. Regression for a critic finding.
test('SNMPv1 trap: non-RFC-3416 PDU kept verbatim + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('snmp/v1-trap').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'snmp'])
    const snmp: any = Layer(decoded, 'snmp').data
    assert.strictEqual(snmp.version, 0, 'SNMPv1')
    assert.strictEqual(snmp.community, 'public')
    assert.strictEqual(snmp.pduType, 0xa4, 'v1 Trap-PDU')
    assert.ok(snmp.pduRaw && snmp.pduRaw.length > 0, 'the trap body is preserved verbatim, not misparsed')
    // The structured request/response fields are absent for a trap (not fabricated from the wrong bytes).
    assert.strictEqual(snmp.requestId, undefined)
})

test('SNMP truncated mid-message: decode survives without throwing', async (): Promise<void> => {
    const full: Buffer = LoadPacket('snmp/get-response').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 6))
})
