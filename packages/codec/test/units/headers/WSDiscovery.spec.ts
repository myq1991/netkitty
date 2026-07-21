import {test} from 'node:test'
import assert from 'node:assert'
import {LoadPacket} from '../../lib/Fixtures'
import {AssertRoundTrip, AssertDecodeSurvives, AssertLayers, Layer, codec} from '../../lib/RoundTrip'
import {CodecDecodeResult} from '../../../src/lib/codec/types/CodecDecodeResult'
import {CodecEncodeResult} from '../../../src/lib/codec/types/CodecEncodeResult'

// WS-Discovery (OASIS, udp:3702) Probe — a SOAP/XML datagram kept verbatim, byte-perfect round-trip. The
// WS-Addressing Action is parsed into display-only metadata (full Action URI + short message type).
test('WS-Discovery Probe: verbatim message + parsed Action + byte-perfect round-trip', async (): Promise<void> => {
    const fixture: {buffer: Buffer} = LoadPacket('wsdiscovery/probe')
    const decoded: CodecDecodeResult[] = await AssertRoundTrip(fixture.buffer)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'wsdiscovery'])
    const wsd: any = Layer(decoded, 'wsdiscovery').data
    assert.strictEqual(wsd.action, 'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe', 'full WS-Addressing Action URI')
    assert.strictEqual(wsd.messageType, 'Probe', 'short message type = last Action path segment')
    // The verbatim message is the whole UDP payload as hex, and it re-emits byte-for-byte.
    assert.ok(wsd.message.startsWith('3c3f786d6c'), 'message begins with the XML declaration "<?xml"')
})

// Crafting: a minimal Hello envelope built from scratch. The whole XML payload is supplied as the
// verbatim message; encode writes it back byte-for-byte and the Action parses to Hello.
test('WS-Discovery faithfully carries a crafted Hello envelope verbatim', async (): Promise<void> => {
    const xml: string = '<?xml version="1.0" encoding="utf-8"?>'
        + '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
        + 'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
        + '<soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</wsa:Action>'
        + '</soap:Header><soap:Body/></soap:Envelope>'
    const message: string = Buffer.from(xml, 'latin1').toString('hex')
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:7f:ff:fa', smac: '00:0c:29:11:22:33', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.10', dip: '239.255.255.250', protocol: 17}},
        {id: 'udp', data: {srcport: 52000, dstport: 3702}},
        {id: 'wsdiscovery', data: {message: message}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    AssertLayers(decoded, ['eth', 'ipv4', 'udp', 'wsdiscovery'])
    const wsd: any = Layer(decoded, 'wsdiscovery').data
    assert.strictEqual(wsd.message, message, 'verbatim message preserved')
    assert.strictEqual(wsd.messageType, 'Hello', 'Action parsed to Hello')
    assert.strictEqual((await codec.encode(decoded)).packet.toString('hex'), packet.toString('hex'), 'byte-perfect')
})

// Negative: non-XML traffic on UDP/3702 must NOT be claimed as WS-Discovery (falls through to raw); and a
// truncated Probe datagram must survive decode without throwing.
test('WS-Discovery rejects non-XML payload on port 3702, and truncation survives', async (): Promise<void> => {
    // A binary (non-'<') payload on udp:3702 — must not be claimed. Use an unsigned byte sequence that
    // does not collide with any content heuristic.
    const {packet}: CodecEncodeResult = await codec.encode([
        {id: 'eth', data: {dmac: '01:00:5e:7f:ff:fa', smac: '00:0c:29:11:22:33', etherType: '0800'}},
        {id: 'ipv4', data: {sip: '192.168.1.10', dip: '239.255.255.250', protocol: 17}},
        {id: 'udp', data: {srcport: 52000, dstport: 3702}},
        {id: 'raw', data: {data: '00010203deadbeef99887766'}}
    ])
    const decoded: CodecDecodeResult[] = await codec.decode(packet)
    assert.ok(!decoded.some((l: CodecDecodeResult): boolean => l.id === 'wsdiscovery'), 'non-XML payload must not be claimed as WS-Discovery')
    assert.strictEqual(decoded[decoded.length - 1].id, 'raw')

    const full: Buffer = LoadPacket('wsdiscovery/probe').buffer
    await AssertDecodeSurvives(full.subarray(0, full.length - 40))
})
