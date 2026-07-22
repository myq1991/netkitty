import {HexToFloat32, HexToInt64, HexToUInt64} from './HexToNumber'

//8/16/32-bit reads use native Buffer accessors instead of the old hex-string roundtrip
//(buffer.toString('hex') → parseInt → TypedArray), which micro-benchmarked ~27x slower per call and
//runs on every scalar field of every packet. Behaviour is preserved bit-for-bit, including the
//best-effort handling of short/truncated buffers: missing high bytes read as 0, so a partial buffer
//yields the value of its available low bytes (verified equivalent across full/short/empty/signed/edge
//cases). Signed reads fall back to an unsigned low-byte read when the buffer is shorter than the type
//width — at less than full width the high (sign) byte is absent, so the value is always non-negative,
//exactly as the hex path produced it. 64-bit and float paths keep their existing implementations
//(64-bit carries clamping semantics; both are comparatively rare).
//
//ONE deliberate semantic change vs the old hex path: for a buffer LONGER than the type width, the
//native readers take the big-endian high bytes (readUInt16BE reads the first 2 octets), whereas the
//old parseInt→TypedArray path wrapped to the low bytes. Big-endian is the correct network-byte-order
//reading. This is only reachable via variable-length callers (SV's BER-TLV getValue('buffer')); the
//fixed-width readBytes(offset,N) callers can never produce an over-wide buffer. Not a round-trip
//regression (over-wide TLVs are re-normalised on encode); affects only a malformed packet's shown value.
/** Read a signed 8-bit integer from the start of `buffer` (0 when empty). */
export const BufferToInt8: (buffer: Buffer) => number = (buffer: Buffer): number => buffer.length ? buffer.readInt8(0) : 0
/** Read a big-endian signed 16-bit integer from the start of `buffer` (short buffers read their available low bytes unsigned). */
export const BufferToInt16: (buffer: Buffer) => number = (buffer: Buffer): number => buffer.length >= 2 ? buffer.readInt16BE(0) : (buffer.length ? buffer.readUIntBE(0, buffer.length) : 0)
/** Read a big-endian signed 32-bit integer from the start of `buffer` (short buffers read their available low bytes unsigned). */
export const BufferToInt32: (buffer: Buffer) => number = (buffer: Buffer): number => buffer.length >= 4 ? buffer.readInt32BE(0) : (buffer.length ? buffer.readUIntBE(0, buffer.length) : 0)
/** Read a big-endian signed 64-bit integer from `buffer` as a bigint (clamped to the int64 range on overflow). */
export const BufferToInt64: (buffer: Buffer) => bigint = (buffer: Buffer): bigint => HexToInt64(buffer.toString('hex'))
/** Read an unsigned 8-bit integer from the start of `buffer` (0 when empty). */
export const BufferToUInt8: (buffer: Buffer) => number = (buffer: Buffer): number => buffer.length ? buffer.readUInt8(0) : 0
/** Read a big-endian unsigned 16-bit integer from the start of `buffer` (short buffers read their available low bytes). */
export const BufferToUInt16: (buffer: Buffer) => number = (buffer: Buffer): number => buffer.length >= 2 ? buffer.readUInt16BE(0) : (buffer.length ? buffer.readUIntBE(0, buffer.length) : 0)
/** Read a big-endian unsigned 32-bit integer from the start of `buffer` (short buffers read their available low bytes). */
export const BufferToUInt32: (buffer: Buffer) => number = (buffer: Buffer): number => buffer.length >= 4 ? buffer.readUInt32BE(0) : (buffer.length ? buffer.readUIntBE(0, buffer.length) : 0)
/** Read a big-endian unsigned 64-bit integer from `buffer` as a bigint (clamped to the uint64 range on overflow). */
export const BufferToUInt64: (buffer: Buffer) => bigint = (buffer: Buffer): bigint => HexToUInt64(buffer.toString('hex'))
/** Read a big-endian IEEE-754 32-bit float from `buffer`. */
export const BufferToFloat32: (buffer: Buffer) => number = (buffer: Buffer): number => HexToFloat32(buffer.toString('hex'))
