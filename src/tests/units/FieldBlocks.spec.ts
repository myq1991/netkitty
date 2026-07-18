import {test} from 'node:test'
import assert from 'node:assert'
import {BaseHeader} from '../../lib/codec/abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../lib/schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../lib/schema/ProtocolFieldJSONSchema'
import {CodecData} from '../../lib/codec/types/CodecData'

/**
 * Direct tests for the declarative field building blocks (BaseHeader.fieldUInt). The migrated
 * headers (UDP/TCP ports) are covered byte-for-byte by golden + differential + round-trip; these
 * exercise the block's edge behavior (out-of-range clamping + recorded error) in isolation.
 */
class FieldTestHeader extends BaseHeader {
    public readonly SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            val: FieldTestHeader.fieldUInt('val', 0, 2, 'Value'),
            byte: FieldTestHeader.fieldUInt('byte', 2, 1, 'Byte')
        }
    }
    public readonly id: string = 'field-test'
    public readonly name: string = 'Field Test'
    public readonly nickname: string = 'FT'
    public match(): boolean {
        return true
    }
    public field(name: string): ProtocolFieldJSONSchema {
        return (this.SCHEMA.properties as {[k: string]: ProtocolFieldJSONSchema})[name]
    }
}

function makeHeader(packet: Buffer): FieldTestHeader {
    const codecData: CodecData = {packet: packet, startPos: 0, postHandlers: []}
    return new FieldTestHeader(codecData, [])
}

test('fieldUInt: decode reads a big-endian unsigned integer into its field', async (): Promise<void> => {
    const header: FieldTestHeader = makeHeader(Buffer.from('123407', 'hex'))
    await header.field('val').decode!.call(header)
    await header.field('byte').decode!.call(header)
    assert.strictEqual((header.instance as any).val.getValue(), 0x1234)
    assert.strictEqual((header.instance as any).byte.getValue(), 0x07)
})

test('fieldUInt: encode writes the value and clamps out-of-range to the field maximum', async (): Promise<void> => {
    const header: FieldTestHeader = makeHeader(Buffer.alloc(3))
    ;(header.instance as any).val.setValue(70000) // > 65535
    await header.field('val').encode!.call(header)
    assert.strictEqual((header.instance as any).val.getValue(), 65535, 'value must be clamped to the 16-bit max')
    assert.strictEqual(header.packet.subarray(0, 2).toString('hex'), 'ffff')
    assert.ok(header.errors.some((e): boolean => e.message.includes('Maximum value is 65535')), 'an out-of-range error must be recorded')
})

test('fieldUInt: encode round-trips an in-range value byte-for-byte', async (): Promise<void> => {
    const header: FieldTestHeader = makeHeader(Buffer.alloc(3))
    ;(header.instance as any).val.setValue(0xABCD)
    await header.field('val').encode!.call(header)
    assert.strictEqual(header.packet.subarray(0, 2).toString('hex'), 'abcd')
})
