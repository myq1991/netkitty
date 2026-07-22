import {test} from 'node:test'
import assert from 'node:assert'
import {readFileSync} from 'node:fs'
import {Lz4FrameDecompress} from '../../src/Lz4FrameDecompress'
import {FixtureCapturePath} from '../lib/Fixtures'

/**
 * The .lz4 fixture is the iec104.pcap fixture compressed with the reference `lz4` CLI (frame format),
 * so decompressing it must reproduce the original pcap byte-for-byte.
 */
test('LZ4 frame: decompresses a real .lz4 to byte-identical original', (): void => {
    const compressed: Buffer = readFileSync(FixtureCapturePath('iec104.pcap.lz4'))
    const original: Buffer = readFileSync(FixtureCapturePath('iec104.pcap'))
    const output: Buffer = Lz4FrameDecompress(compressed)
    assert.strictEqual(output.length, original.length)
    assert.ok(output.equals(original), 'decompressed bytes must equal the original pcap')
})

test('LZ4 frame: leading magic is the standard frame magic (04 22 4d 18)', (): void => {
    const compressed: Buffer = readFileSync(FixtureCapturePath('iec104.pcap.lz4'))
    assert.strictEqual(compressed.readUInt32BE(0), 0x04224d18)
})

test('LZ4 frame: a hand-built frame with a stored (uncompressed) block round-trips', (): void => {
    const payload: Buffer = Buffer.from('hello lz4 stored block', 'ascii')
    const frame: Buffer = Buffer.concat([
        Buffer.from([0x04, 0x22, 0x4d, 0x18]), //magic
        Buffer.from([0x60]),                   //FLG: version 01, block-independent
        Buffer.from([0x70]),                   //BD: 4 MB max block size
        Buffer.from([0x00]),                   //HC (not verified)
        (() => { const n: Buffer = Buffer.alloc(4); n.writeUInt32LE((payload.length | 0x80000000) >>> 0, 0); return n })(),
        payload,
        Buffer.from([0x00, 0x00, 0x00, 0x00])  //EndMark
    ])
    assert.ok(Lz4FrameDecompress(frame).equals(payload))
})

test('LZ4 frame: rejects a non-LZ4 buffer with a clear error', (): void => {
    assert.throws((): Buffer => Lz4FrameDecompress(Buffer.from('not an lz4 frame at all', 'ascii')), /bad magic number/)
})
