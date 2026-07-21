import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, LayerIds, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'

// Real LDAPv3 bindRequest (simple auth, cn=admin,dc=example,dc=org), captured from ldapwhoami against
// osixia/openldap on loopback. RFC 4511, ASN.1 BER: SEQUENCE { messageID INTEGER, protocolOp }.
test('LDAP bindRequest: BER decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('ldap/bind').buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'ldap'])
    const ldap: any = Layer(decoded, 'ldap').data
    assert.strictEqual(ldap.messageID, 1, 'messageID')
    assert.strictEqual(ldap.protocolOpTag, 0x60, 'bindRequest application tag (0x60 = 96)')
    assert.ok(ldap.protocolOpData && ldap.protocolOpData.length > 0, 'protocolOp body kept verbatim')
    // The verbatim body carries the LDAPv3 version, bind DN and simple-auth password bytes.
    assert.ok(ldap.protocolOpData.includes(Buffer.from('cn=admin,dc=example,dc=org').toString('hex')), 'bind DN present in body')
})

// Crafted searchRequest (protocolOp 0x63). Encode is a faithful executor: a standard minimal-BER message
// must re-encode byte-identically through decode → encode.
test('LDAP searchRequest: crafted op 0x63 re-encodes byte-identically', async (): Promise<void> => {
    // Body of a real searchRequest (base dc=example,dc=org, scope wholeSubtree, filter present=cn,
    // attributes {cn}) captured on the wire — kept verbatim after the 0x63 tag.
    const protocolOpData: string = '35041164633d6578616d706c652c64633d6f72670a01020a0100020100020100010100a30b0402636e040561646d696e30040402636e'
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 59624, dstport: 389}},
        {id: 'ldap', data: {messageID: 2, protocolOpTag: 0x63, protocolOpData}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'tcp', 'ldap'])
    const ldap: any = Layer(decoded, 'ldap').data
    assert.strictEqual(ldap.messageID, 2)
    assert.strictEqual(ldap.protocolOpTag, 0x63, 'searchRequest')
    assert.strictEqual(ldap.protocolOpData, protocolOpData, 'search body round-trips verbatim')
    const {packet: reencoded}: {packet: Buffer} = await codec.encode(decoded)
    assert.strictEqual(reencoded.toString('hex'), packet.toString('hex'), 'byte-perfect re-encode')
})

// UnbindRequest (protocolOp 0x42) is the minimal LDAP op — an empty [APPLICATION 2] NULL body. It must
// round-trip byte-for-byte (SEQUENCE { messageID, 42 00 }).
test('LDAP unbindRequest: minimal empty-body op round-trips', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 59620, dstport: 389}},
        {id: 'ldap', data: {messageID: 3, protocolOpTag: 0x42, protocolOpData: '00'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const ldap: any = Layer(decoded, 'ldap').data
    assert.strictEqual(ldap.messageID, 3)
    assert.strictEqual(ldap.protocolOpTag, 0x42, 'unbindRequest')
    assert.strictEqual(ldap.protocolOpData, '00', 'empty-body NULL preserved')
    const {packet: reencoded}: {packet: Buffer} = await codec.encode(decoded)
    assert.strictEqual(reencoded.toString('hex'), packet.toString('hex'), 'byte-perfect re-encode')
})

// A multi-byte messageID (256 = 02 02 01 00) must survive the BER INTEGER two's-complement round-trip
// and re-encode with minimal-definite length.
test('LDAP multi-byte messageID (256) round-trips through BER INTEGER', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 59626, dstport: 389}},
        {id: 'ldap', data: {messageID: 256, protocolOpTag: 0x42, protocolOpData: '00'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const ldap: any = Layer(decoded, 'ldap').data
    assert.strictEqual(ldap.messageID, 256, 'multi-byte messageID survives')
    const {packet: reencoded}: {packet: Buffer} = await codec.encode(decoded)
    assert.strictEqual(reencoded.toString('hex'), packet.toString('hex'), 'byte-perfect re-encode')
})

// Non-LDAP payload on port 389 (first byte not 0x30) must NOT be claimed by LDAP — it falls through to
// RawData. And a truncated LDAP message must decode without throwing.
test('LDAP guards: non-SEQUENCE on 389 → raw; truncation survives', async (): Promise<void> => {
    const notLdap: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 389}},
        {id: 'raw', data: {data: 'deadbeefcafe'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(notLdap.packet)
    assert.ok(!LayerIds(decoded).includes('ldap'), 'non-SEQUENCE bytes on 389 are not misclaimed as LDAP')

    const full: Buffer = LoadPacket('ldap/bind').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 8))
})

// Regression: a malformed LDAP frame carrying a NEGATIVE messageID (a signed BER INTEGER 0xff = -1) must
// decode AND re-encode without throwing — the messageID bounds allow the signed range so decode→encode
// stays total (previously the encode-entry Ajv minimum:0 gate threw on the decoded -1).
test('LDAP negative messageID (malformed signed BER INTEGER) round-trips without throwing', async (): Promise<void> => {
    const {packet}: {packet: Buffer} = await codec.encode([
        {id: 'eth', data: {dmac: '00:00:00:00:00:00', smac: '00:00:00:00:00:00', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '127.0.0.1', dip: '127.0.0.1', protocol: 6}},
        {id: 'tcp', data: {srcport: 40000, dstport: 389}},
        {id: 'raw', data: {data: '30050201ff4200'}} // SEQUENCE{ INTEGER -1, [APPLICATION 2] UnbindRequest }
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    const ldap: any = Layer(decoded, 'ldap').data
    assert.strictEqual(ldap.messageID, -1, 'the signed BER INTEGER decodes to -1')
    // Re-encode must not throw and must reproduce the malformed frame byte-for-byte.
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'negative messageID re-encodes faithfully')
})
