/**
 * Pure-JS, dependency-free LZ4 frame-format decompressor (LZ4 frame spec v1.6.x, magic 0x184D2204),
 * used to transparently read `.lz4`-compressed capture files. Decompress-only and browser-safe. It
 * verifies the frame magic and descriptor, walks the data blocks (compressed or stored), and skips the
 * optional block/content checksums. A structurally invalid frame header (too short, bad magic, or an
 * unsupported version) throws — callers that must tolerate arbitrary bytes should catch. Within a valid
 * frame, malformed block contents degrade to best-effort output rather than crashing or hanging:
 * out-of-range reads yield 0, out-of-range writes are ignored (Node Buffer semantics), an illegal zero
 * match-offset ends the block, and every loop strictly advances. DictID and skippable frames are not
 * supported.
 */
const LZ4_FRAME_MAGIC: number = 0x184d2204
const BLOCK_MAX_SIZE: Record<number, number> = {4: 65536, 5: 262144, 6: 1048576, 7: 4194304}

export function Lz4FrameDecompress(input: Buffer): Buffer {
    if (input.length < 7 || input.readUInt32LE(0) !== LZ4_FRAME_MAGIC) {
        throw new Error('not an LZ4 frame (bad magic number)')
    }
    let pos: number = 4
    const flg: number = input[pos++]
    const bd: number = input[pos++]
    if ((flg >> 6) !== 0x01) throw new Error(`unsupported LZ4 frame version: ${flg >> 6}`)
    const contentSizePresent: boolean = ((flg >> 3) & 1) === 1
    const dictIdPresent: boolean = (flg & 1) === 1
    const blockChecksum: boolean = ((flg >> 4) & 1) === 1
    const blockMaxSize: number = BLOCK_MAX_SIZE[(bd >> 4) & 0x07] ?? 4194304
    if (contentSizePresent) pos += 8
    if (dictIdPresent) pos += 4
    pos += 1 //header checksum (HC) — not verified
    const chunks: Buffer[] = []
    while (pos + 4 <= input.length) {
        const blockSizeField: number = input.readUInt32LE(pos)
        pos += 4
        if (blockSizeField === 0) break //EndMark
        const stored: boolean = (blockSizeField & 0x80000000) !== 0
        const blockSize: number = blockSizeField & 0x7fffffff
        const blockEnd: number = Math.min(pos + blockSize, input.length)
        chunks.push(stored ? Buffer.from(input.subarray(pos, blockEnd)) : Lz4DecodeBlock(input, pos, blockEnd, blockMaxSize))
        pos = blockEnd
        if (blockChecksum) pos += 4
    }
    return Buffer.concat(chunks)
}

/** Decompress one LZ4 block (LZ4 block format) from input[start, end) into a new Buffer (≤ blockMaxSize). */
function Lz4DecodeBlock(input: Buffer, start: number, end: number, blockMaxSize: number): Buffer {
    const out: Buffer = Buffer.allocUnsafe(blockMaxSize)
    let s: number = start
    let d: number = 0
    while (s < end) {
        const token: number = input[s++]
        //literals: high nibble is the length (0xF means read continuation bytes until one < 0xFF)
        let literalLength: number = token >> 4
        if (literalLength === 15) {
            let extra: number
            do { extra = input[s++]; literalLength += extra } while (extra === 255)
        }
        for (let i: number = 0; i < literalLength; i++) out[d++] = input[s++]
        if (s >= end) break //final sequence has literals only, no match
        //match: 2-byte little-endian back-offset, then the low nibble is (length − 4), same 0xF continuation
        const offset: number = input[s] | (input[s + 1] << 8)
        s += 2
        if (offset === 0) break //illegal in LZ4; bail rather than read uninitialized output memory (m === d)
        let matchLength: number = token & 0x0f
        if (matchLength === 15) {
            let extra: number
            do { extra = input[s++]; matchLength += extra } while (extra === 255)
        }
        matchLength += 4
        let m: number = d - offset
        for (let i: number = 0; i < matchLength; i++) out[d++] = out[m++] //may overlap (RLE-style)
    }
    return Buffer.from(out.subarray(0, d))
}
