import {Float32ToHex, Int64ToHex, UInt64ToHex} from './NumberToHex'

//8/16/32-bit writes use native Buffer accessors instead of number→hex-string→Buffer. Int and UInt
//emit identical bytes (the field's low bytes, big-endian), so both go through the unsigned writer
//after masking to the field width — matching the old hex path, whose TypedArray view also wrote the
//value's low bytes. In-range values (the only ones encode produces, after Ajv coercion + field clamp)
//are byte-for-byte identical, which the round-trip fixtures enforce. Out-of-range values wrap to the
//field width here (a cleaner, well-defined result than the old odd-length-hex nibble truncation).
//64-bit and float keep their existing implementations.
/** Write a signed 8-bit integer to a 1-byte buffer (value masked to the field width). */
export const Int8ToBuffer: (value: number) => Buffer = (value: number): Buffer => { const buffer: Buffer = Buffer.allocUnsafe(1); buffer.writeUInt8(value & 0xff, 0); return buffer }
/** Write a signed 16-bit integer to a big-endian 2-byte buffer (value masked to the field width). */
export const Int16ToBuffer: (value: number) => Buffer = (value: number): Buffer => { const buffer: Buffer = Buffer.allocUnsafe(2); buffer.writeUInt16BE(value & 0xffff, 0); return buffer }
/** Write a signed 32-bit integer to a big-endian 4-byte buffer (value masked to the field width). */
export const Int32ToBuffer: (value: number) => Buffer = (value: number): Buffer => { const buffer: Buffer = Buffer.allocUnsafe(4); buffer.writeUInt32BE(value >>> 0, 0); return buffer }
/** Write a signed 64-bit bigint to a big-endian 8-byte buffer. */
export const Int64ToBuffer: (value: bigint) => Buffer = (value: bigint): Buffer => Buffer.from(Int64ToHex(value), 'hex')
/** Write an unsigned 8-bit integer to a 1-byte buffer (value masked to the field width). */
export const UInt8ToBuffer: (value: number) => Buffer = (value: number): Buffer => { const buffer: Buffer = Buffer.allocUnsafe(1); buffer.writeUInt8(value & 0xff, 0); return buffer }
/** Write an unsigned 16-bit integer to a big-endian 2-byte buffer (value masked to the field width). */
export const UInt16ToBuffer: (value: number) => Buffer = (value: number): Buffer => { const buffer: Buffer = Buffer.allocUnsafe(2); buffer.writeUInt16BE(value & 0xffff, 0); return buffer }
/** Write an unsigned 32-bit integer to a big-endian 4-byte buffer (value masked to the field width). */
export const UInt32ToBuffer: (value: number) => Buffer = (value: number): Buffer => { const buffer: Buffer = Buffer.allocUnsafe(4); buffer.writeUInt32BE(value >>> 0, 0); return buffer }
/** Write an unsigned 64-bit bigint to a big-endian 8-byte buffer. */
export const UInt64ToBuffer: (value: bigint) => Buffer = (value: bigint): Buffer => Buffer.from(UInt64ToHex(value), 'hex')
/** Write an IEEE-754 32-bit float to a big-endian 4-byte buffer. */
export const Float32ToBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(Float32ToHex(value), 'hex')
