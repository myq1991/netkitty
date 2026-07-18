import {test} from 'node:test'
import assert from 'node:assert'
import {BaseHeader} from '../../src/lib/codec/abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../src/lib/schema/ProtocolJSONSchema'
import {CodecData} from '../../src/lib/codec/types/CodecData'

/**
 * Minimal concrete header that exposes the protected bit helpers so their precision can be tested
 * directly (readBits/writeBits are the shared primitive under every bitfield in every protocol).
 */
class BitsTestHeader extends BaseHeader {
    public readonly SCHEMA: ProtocolJSONSchema = {type: 'object', properties: {}}
    public readonly id: string = 'bits-test'
    public readonly name: string = 'Bits Test'
    public readonly nickname: string = 'BITS'
    public match(): boolean {
        return true
    }
    public rb(offset: number, length: number, bitOffset: number, bitLength: number): number {
        return this.readBits(offset, length, bitOffset, bitLength)
    }
    public wb(offset: number, length: number, bitOffset: number, bitLength: number, value: number): void {
        this.writeBits(offset, length, bitOffset, bitLength, value)
    }
}

function makeHeader(packet: Buffer): BitsTestHeader {
    const codecData: CodecData = {packet: packet, startPos: 0, postHandlers: []}
    return new BitsTestHeader(codecData, [])
}

// The old string-based readBits used parseInt(hex) which silently lost precision past 2^53, so a
// bitfield read from a window wider than ~6 octets returned a wrong number. The BigInt version is
// exact for any window width.
test('readBits: 40-bit field from an 8-octet window is exact (no >2^53 precision loss)', (): void => {
    // Window bytes: FF FF FF FF FF 00 00 00 — top 40 bits are all ones = 0xFFFFFFFFFF.
    const header: BitsTestHeader = makeHeader(Buffer.from('ffffffffff000000', 'hex'))
    assert.strictEqual(header.rb(0, 8, 0, 40), 0xFFFFFFFFFF, 'must equal 1099511627775, not a rounded value')
})

test('writeBits/readBits: a >32-bit value round-trips exactly through a wide window', (): void => {
    const header: BitsTestHeader = makeHeader(Buffer.alloc(8))
    const value: number = 0x13579BDF02 // 40-bit value > 2^32
    header.wb(0, 8, 0, 40, value)
    assert.strictEqual(header.rb(0, 8, 0, 40), value)
    // The low 24 bits of the window must remain untouched by a [0,40) write.
    assert.strictEqual(header.rb(0, 8, 40, 24), 0)
})

test('readBits/writeBits: narrow bitfields still behave (byte-level flags)', (): void => {
    const header: BitsTestHeader = makeHeader(Buffer.from('00', 'hex'))
    header.wb(0, 1, 0, 1, 1) // set the MSB
    assert.strictEqual(header.rb(0, 1, 0, 1), 1)
    assert.strictEqual(header.rb(0, 1, 1, 7), 0)
    assert.strictEqual(header.packet[0], 0x80)
})
