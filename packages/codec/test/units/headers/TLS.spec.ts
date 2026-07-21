import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, Layer, Decode, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/types/CodecDecodeResult'

test('TLS 1.2 application data record: field decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tls/tls12-record').buffer)
    const tls: any = Layer(decoded, 'tls-appdata').data
    assert.strictEqual(tls.contentType, 23)
    assert.strictEqual(tls.version, 'TLS1.2')
    assert.strictEqual(tls.length, 86)
})

test('TLS record (second sample): decode + round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tls/record-2').buffer)
    Layer(decoded, 'tls-appdata')
})

// BUG #3 (REAL) — TLS_Alert.ts:47-48 defines both code_120 and code_255 with the identical
// string 'No application protocol'. Alert 255 is unassigned by RFC 8446 §6 (the last defined
// alert is 120, no_application_protocol; tshark reports "Unknown (255)"). Decoding description
// 255 yields 'No application protocol'; the encode switch reaches `case code_120` first (same
// enum value), leaving `case code_255` unreachable, so the octet is rewritten 255 -> 120.
// Correct behavior: the description octet must round-trip unchanged (and 255 should not share a
// label with 120). The description is the final octet of this record.
test('TLS Alert description 255: round-trip must preserve the description octet', async (): Promise<void> => {
    const buffer: Buffer = LoadPacket('tls/alert-no-app-protocol').buffer
    const decoded: CodecDecodeResult[] = await Decode(buffer)
    const alert: any = Layer(decoded, 'tls-alert').data
    assert.strictEqual(alert.contentType, 21)
    assert.strictEqual(alert.levelType, 'Fatal')
    const encoded = await codec.encode(decoded)
    // Fails today: 255 collapses to 120 because code_255 duplicates code_120.
    assert.strictEqual(encoded.packet[encoded.packet.length - 1], 0xff,
        'alert description octet 255 must be preserved, not collapsed to 120')
})

// BUG #4 (REAL) — TLS_Handshake.ts:288-290 reads the message body using the 3-byte
// handshakeLength (up to 16 MB) instead of bounding it by the record-layer `length` (2 bytes).
// When a handshake message is fragmented across TLS records, decode reads past the current
// record boundary. This fixture: record 1 is a Client Hello *fragment* (record length 8, but
// handshakeLength claims 16) followed by a separate Application Data record. tshark ground
// truth: "[Client Hello Fragment], Application Data" (two records). Correct behavior: the
// handshake body must stop at the record boundary (length-4 = 4 bytes) and the following
// Application Data record must decode as its own layer.
test('TLS fragmented handshake: message body must not cross the TLS record boundary', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await Decode(LoadPacket('tls/handshake-fragment').buffer)
    const hs: any = Layer(decoded, 'tls-handshake').data
    assert.strictEqual(hs.contentType, 22)
    assert.strictEqual(hs.length, 8, 'TLS record-layer length')
    // The 4-byte fragment 'aabbccdd' is not a structurable ClientHello, so it is preserved as
    // messagedata.raw (not extended past the record boundary into the next record's bytes).
    assert.strictEqual(hs.messagedata.raw.toLowerCase(), 'aabbccdd',
        'handshake body must stop at the record boundary, not read handshakeLength bytes')
    Layer(decoded, 'tls-appdata') // the trailing record must decode as its own layer
})

// TLS handshake bodies are structurally decoded for ClientHello/ServerHello and preserved as
// messagedata.raw otherwise (or on parse failure). Both paths must round-trip byte-for-byte.
test('TLS ClientHello: structured decode + byte-perfect round-trip', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tls/clienthello').buffer)
    const hs: any = Layer(decoded, 'tls-handshake').data
    assert.strictEqual(hs.handshakeType, 'ClientHello')
    assert.strictEqual(hs.messagedata.version, 'TLS1.2', 'ClientHello version must be structured')
    assert.deepStrictEqual(hs.messagedata.cipherSuites, ['002f', '0035'], 'cipher suites must be structured into a list')
    assert.deepStrictEqual(hs.messagedata.compressionMethods, ['00'])
    assert.strictEqual(hs.messagedata.raw, undefined, 'a structured ClientHello must not carry a raw fallback')
    // extensions must be split into individual entries, each structurally decoded per its spec
    const extensions: any[] = hs.messagedata.extensions
    const byName: (n: string) => any = (n: string): any => extensions.find((e: any): boolean => e.name === n)
    // server_name → readable hostname (not a hex blob)
    assert.deepStrictEqual(byName('server_name').serverNames, [{nameType: 'host_name', hostName: 'example.com'}])
    // ALPN → ascii protocol list
    assert.deepStrictEqual(byName('application_layer_protocol_negotiation').protocols, ['h2', 'http/1.1'])
    // supported_versions → friendly version names
    assert.deepStrictEqual(byName('supported_versions').versions, ['TLS1.3', 'TLS1.2'])
    assert.deepStrictEqual(byName('supported_groups').groups, ['001d', '0017'])
    assert.strictEqual(byName('key_share').keyShares[0].group, '001d')
    // an unknown extension type must be preserved as hex, not dropped
    const unknown: any = extensions.find((e: any): boolean => e.type === '1234')
    assert.strictEqual(unknown.data, 'deadbeef', 'unknown extension must keep its raw hex data')
    assert.strictEqual(unknown.serverNames, undefined)
})

test('TLS unstructured handshake body is preserved as raw and round-trips', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tls/handshake-fragment').buffer)
    const hs: any = Layer(decoded, 'tls-handshake').data
    assert.ok(hs.messagedata.raw, 'an unstructurable handshake body must be surfaced as messagedata.raw')
    assert.strictEqual(hs.messagedata.version, undefined, 'no structured fields for an unstructurable body')
})

// RFC 6520 §4: a HeartbeatMessage carries mandatory padding (>= 16 octets) after the payload;
// it must be decoded into a visible field and reproduced on re-encode (previously dropped).
test('TLS Heartbeat: mandatory padding is preserved and round-trips', async (): Promise<void> => {
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(LoadPacket('tls/heartbeat').buffer)
    const hb: any = Layer(decoded, 'tls-heartbeat').data
    assert.strictEqual(hb.heartbeatType, 'HeartbeatRequest')
    assert.strictEqual(hb.payloadMessage, 'deadbeef')
    assert.strictEqual(hb.padding, 'abababababababababababababababab', 'the >=16-byte padding must be preserved')
})
