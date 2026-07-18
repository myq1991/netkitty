import {test} from 'node:test'
import assert from 'node:assert'
import {Codec} from '../../src/lib/codec/Codec'
import {LoadPacket} from '../lib/Fixtures'
import {DissectionField, DissectionLayer} from '../../src/lib/codec/types/Dissection'

const codec: Codec = new Codec()

function layer(layers: DissectionLayer[], id: string): DissectionLayer {
    const found: DissectionLayer | undefined = layers.find((l: DissectionLayer): boolean => l.id === id)
    assert.ok(found, `expected dissected layer '${id}'`)
    return found!
}
function field(fields: DissectionField[], name: string): DissectionField {
    const found: DissectionField | undefined = fields.find((f: DissectionField): boolean => f.name === name)
    assert.ok(found, `expected field '${name}'`)
    return found!
}

// 3a: every scalar field carries the exact bytes it occupies in the packet (Wireshark's core view).
test('dissect: scalar fields report the correct absolute byte range and raw bytes', async (): Promise<void> => {
    const layers: DissectionLayer[] = await codec.dissect(LoadPacket('tcp/uto-option').buffer)

    const etherType: DissectionField = field(layer(layers, 'eth').fields, 'etherType')
    assert.deepStrictEqual({offset: etherType.offset, length: etherType.length, rawBytes: etherType.rawBytes}, {offset: 12, length: 2, rawBytes: '0800'})
    assert.strictEqual(etherType.label, 'EtherType')

    const ttl: DissectionField = field(layer(layers, 'ipv4').fields, 'ttl')
    assert.deepStrictEqual({offset: ttl.offset, length: ttl.length, rawBytes: ttl.rawBytes, value: ttl.value}, {offset: 22, length: 1, rawBytes: '40', value: 64})

    const sip: DissectionField = field(layer(layers, 'ipv4').fields, 'sip')
    assert.deepStrictEqual({offset: sip.offset, length: sip.length, rawBytes: sip.rawBytes}, {offset: 26, length: 4, rawBytes: '0a000001'})

    // TCP starts at byte 34 (14 eth + 20 ip); srcport 12345 = 0x3039.
    const srcport: DissectionField = field(layer(layers, 'tcp').fields, 'srcport')
    assert.deepStrictEqual({offset: srcport.offset, length: srcport.length, rawBytes: srcport.rawBytes}, {offset: 34, length: 2, rawBytes: '3039'})
})

test('dissect: nested fields become children (e.g. IPv4 DS field)', async (): Promise<void> => {
    const layers: DissectionLayer[] = await codec.dissect(LoadPacket('tcp/uto-option').buffer)
    const dsfield: DissectionField = field(layer(layers, 'ipv4').fields, 'dsfield')
    assert.ok(dsfield.children && dsfield.children.length >= 2, 'dsfield must expose dscp/ecn as children')
    assert.ok(dsfield.children!.some((c: DissectionField): boolean => c.name === 'dscp'))
})

test('dissect: values match the plain decode (same engine, no second parser)', async (): Promise<void> => {
    const buffer: Buffer = LoadPacket('tcp/uto-option').buffer
    const tcpLayer: any = (await codec.decode(buffer)).find((l: any): boolean => l.id === 'tcp')
    const decoded: any = tcpLayer.data
    const dissected: DissectionLayer[] = await codec.dissect(buffer)
    assert.strictEqual(field(layer(dissected, 'tcp').fields, 'srcport').value, decoded.srcport)
    assert.strictEqual(field(layer(dissected, 'tcp').fields, 'dstport').value, decoded.dstport)
})

test('dissect: a field carrying a decode error is marked severity error (expert info)', async (): Promise<void> => {
    // sv/baseline has an unparseable savPdu, recorded as an error on path 'svPdu'.
    const layers: DissectionLayer[] = await codec.dissect(LoadPacket('sv/baseline').buffer)
    const sv: DissectionLayer = layer(layers, 'sv')
    assert.ok(sv.errors.length > 0, 'the SV layer must carry accumulated errors')
    assert.strictEqual(field(sv.fields, 'svPdu').severity, 'error')
})
